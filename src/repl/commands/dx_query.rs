//! The expressions `dx` evaluates over the debugger data model, as WinDbg's
//! LINQ-style queries write them: paths (`@$curprocess.Threads[0x1c]`),
//! queries with lambdas (`.Where(p => p.Name == "lsass.exe")`, `.Select`,
//! `.OrderBy`, ...), anonymous objects (`new { Name = p.Name }`), string
//! methods, C++ operators and casts, and
//! `Debugger.Utility.Collections.FromListEntry`. Whatever is not part of the
//! model, such as `nt!PsActiveProcessHead`, `@rcx`, or a kernel object's
//! fields, is a typed expression that the expression evaluator reads.

use std::cmp::Ordering;
use std::collections::HashSet;

use crate::error::{Error, Result};
use crate::expr::{Expr, ExprValue, NumberRadix};
use crate::layout::{ParsedType, is_signed_primitive};
use crate::target::Target;
use crate::types::VirtAddr;

use super::dx_model::{self as model, Integer, ModelValue, ROOTS};

/// The most entries `FromListEntry` walks before it stops.
const MAX_LIST_ENTRIES: usize = 1 << 20;

/// The collection queries `dx` evaluates.
const QUERIES: &str = "Where, Select, SelectMany, First, Last, Any, All, Count, OrderBy, \
                       OrderByDescending, Take, and Skip";

/// The string methods `dx` evaluates.
const STRING_METHODS: &str = "Contains, StartsWith, EndsWith, ToLower, ToUpper, and Length";

/// Operators by precedence, loosest first.
const BINARY_LEVELS: [&[&str]; 10] = [
    &["||"],
    &["&&"],
    &["|"],
    &["^"],
    &["&"],
    &["==", "!="],
    &["<", ">", "<=", ">="],
    &["<<", ">>"],
    &["+", "-"],
    &["*", "/", "%"],
];

/// Punctuation, the longest first so `==` is not read as `=`.
const PUNCTUATION: [&str; 33] = [
    "=>", "->", "==", "!=", "<=", ">=", "&&", "||", "<<", ">>", "(", ")", "[", "]", "{", "}", ",",
    ".", "<", ">", "+", "-", "*", "/", "%", "&", "|", "^", "!", "~", "?", ":", "=",
];

/// The C++ type names a cast can start with besides a module-qualified one
/// (`nt!_TOKEN`) or a pointer.
const PRIMITIVE_TYPES: [&str; 14] = [
    "char",
    "short",
    "int",
    "long",
    "unsigned",
    "signed",
    "bool",
    "__int64",
    "UCHAR",
    "USHORT",
    "ULONG",
    "ULONG64",
    "ULONGLONG",
    "wchar_t",
];

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Name(String),
    Int(Integer),
    Str(String),
    Punct(&'static str),
}

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidExpression(message.into())
}

/// An error's message without the kind an invalid expression's display
/// adds, to nest it in another.
fn message(error: &Error) -> String {
    match error {
        Error::InvalidExpression(message) => message.clone(),
        other => other.to_string(),
    }
}

fn name_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || matches!(ch, '_' | '@' | '$')
}

fn name_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$')
}

/// A C++ integer literal: hex with `0x`, decimal otherwise (or with `0n`),
/// with WinDbg's backtick separators and `u`/`l` suffixes. As in WinDbg's
/// `dx`, a literal is an `int` when it fits one and an `__int64` (wrapping,
/// so `0xffffffffffffffff` is -1) when not, and a `u` suffix makes it
/// unsigned.
fn parse_int(text: &str) -> Result<Token> {
    let clean: String = text.chars().filter(|ch| *ch != '`').collect();
    let lower = clean.to_ascii_lowercase();
    let (digits, radix) = if let Some(hex) = lower.strip_prefix("0x") {
        (hex.trim_end_matches(['u', 'l']), 16)
    } else if let Some(decimal) = lower.strip_prefix("0n") {
        (decimal.trim_end_matches(['u', 'l']), 10)
    } else {
        (lower.trim_end_matches(['u', 'l']), 10)
    };
    let value = u64::from_str_radix(digits, radix)
        .map_err(|_| invalid(format!("{text} is not a number")))?;
    let unsigned = lower.contains('u');
    let narrow = if unsigned {
        u32::try_from(value).is_ok()
    } else {
        i32::try_from(value).is_ok()
    };
    Ok(Token::Int(Integer::new(
        i128::from(value),
        unsigned,
        !narrow,
    )))
}

fn tokenize(text: &str) -> Result<Vec<Token>> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        let ch = chars[at];
        if ch.is_whitespace() {
            at += 1;
        } else if ch.is_ascii_digit() {
            let start = at;
            while at < chars.len() && (chars[at].is_ascii_alphanumeric() || chars[at] == '`') {
                at += 1;
            }
            tokens.push(parse_int(&chars[start..at].iter().collect::<String>())?);
        } else if name_start(ch) {
            let start = at;
            at += 1;
            while at < chars.len() {
                // `nt!PsActiveProcessHead`: a `!` between a module and a
                // name; `a!=b` and `!x` are operators.
                let module_bang =
                    chars[at] == '!' && chars.get(at + 1).is_some_and(|next| name_start(*next));
                if !(name_char(chars[at]) || module_bang) {
                    break;
                }
                at += 1;
            }
            tokens.push(Token::Name(chars[start..at].iter().collect()));
        } else if ch == '"' {
            at += 1;
            let mut text = String::new();
            loop {
                match chars.get(at) {
                    None => return Err(invalid("a string is missing its closing quote")),
                    Some('"') => break,
                    Some('\\') => {
                        at += 1;
                        text.push(match chars.get(at) {
                            Some('n') => '\n',
                            Some('t') => '\t',
                            Some(other) => *other,
                            None => return Err(invalid("a string ends in a backslash")),
                        });
                    }
                    Some(other) => text.push(*other),
                }
                at += 1;
            }
            at += 1;
            tokens.push(Token::Str(text));
        } else {
            let rest: String = chars[at..chars.len().min(at + 2)].iter().collect();
            let punct = PUNCTUATION
                .iter()
                .find(|punct| rest.starts_with(**punct))
                .ok_or_else(|| invalid(format!("unexpected '{ch}'")))?;
            tokens.push(Token::Punct(punct));
            at += punct.len();
        }
    }
    Ok(tokens)
}

/// Whether `text` is for the data model evaluator: it reads a data model
/// root or makes an object with `new`. Anything else is a typed expression.
pub fn is_query(text: &str) -> bool {
    let Ok(tokens) = tokenize(text) else {
        return false;
    };
    tokens.iter().enumerate().any(|(index, token)| match token {
        Token::Name(name) if ROOTS.contains(&name.as_str()) => true,
        Token::Name(name) if name == "new" => tokens.get(index + 1) == Some(&Token::Punct("{")),
        _ => false,
    })
}

#[derive(Debug, Clone)]
enum Node {
    Int(Integer),
    Str(String),
    Bool(bool),
    Name(String),
    Member(Box<Node>, String),
    Arrow(Box<Node>, String),
    Index(Box<Node>, Box<Node>),
    Call(Box<Node>, String, Vec<Node>),
    Unary(&'static str, Box<Node>),
    Binary(&'static str, Box<Node>, Box<Node>),
    Conditional(Box<Node>, Box<Node>, Box<Node>),
    Cast(String, Box<Node>),
    New(Vec<(String, Node)>),
    Lambda(String, Box<Node>),
}

struct Parser {
    tokens: Vec<Token>,
    at: usize,
    /// The lambda parameters in scope, which a parenthesized name never
    /// casts to.
    params: Vec<String>,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn peek_at(&self, offset: usize) -> Option<&Token> {
        self.tokens.get(self.at + offset)
    }

    fn is_punct(&self, punct: &str) -> bool {
        matches!(self.peek(), Some(Token::Punct(found)) if *found == punct)
    }

    fn eat(&mut self, punct: &str) -> bool {
        let found = self.is_punct(punct);
        if found {
            self.at += 1;
        }
        found
    }

    fn expect(&mut self, punct: &str) -> Result<()> {
        if self.eat(punct) {
            Ok(())
        } else {
            Err(invalid(match self.peek() {
                Some(token) => format!("expected '{punct}' before {}", describe(token)),
                None => format!("expected '{punct}' at the end"),
            }))
        }
    }

    fn name(&mut self) -> Result<String> {
        match self.peek().cloned() {
            Some(Token::Name(name)) => {
                self.at += 1;
                Ok(name)
            }
            Some(other) => Err(invalid(format!(
                "expected a name, not {}",
                describe(&other)
            ))),
            None => Err(invalid("expected a name at the end")),
        }
    }

    fn expression(&mut self) -> Result<Node> {
        // `p => ...` and `(p) => ...`.
        let lambda = match (
            self.peek(),
            self.peek_at(1),
            self.peek_at(2),
            self.peek_at(3),
        ) {
            (Some(Token::Name(name)), Some(Token::Punct("=>")), _, _) => Some((name.clone(), 2)),
            (
                Some(Token::Punct("(")),
                Some(Token::Name(name)),
                Some(Token::Punct(")")),
                Some(Token::Punct("=>")),
            ) => Some((name.clone(), 4)),
            _ => None,
        };
        if let Some((param, skip)) = lambda {
            self.at += skip;
            self.params.push(param.clone());
            let body = self.expression();
            self.params.pop();
            return Ok(Node::Lambda(param, Box::new(body?)));
        }
        let condition = self.binary(0)?;
        if !self.eat("?") {
            return Ok(condition);
        }
        let then = self.expression()?;
        self.expect(":")?;
        let otherwise = self.expression()?;
        Ok(Node::Conditional(
            Box::new(condition),
            Box::new(then),
            Box::new(otherwise),
        ))
    }

    fn binary(&mut self, level: usize) -> Result<Node> {
        if level == BINARY_LEVELS.len() {
            return self.unary();
        }
        let mut left = self.binary(level + 1)?;
        while let Some(Token::Punct(op)) = self.peek() {
            let Some(op) = BINARY_LEVELS[level].iter().find(|known| *known == op) else {
                break;
            };
            self.at += 1;
            let right = self.binary(level + 1)?;
            left = Node::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Node> {
        for op in ["-", "~", "!", "*", "&"] {
            if self.eat(op) {
                let operand = self.unary()?;
                return Ok(match (op, operand) {
                    // `-2147483648` is an `__int64` before it is negated.
                    ("-", Node::Int(integer)) => {
                        Node::Int(Integer::new(-integer.value, integer.unsigned, integer.wide))
                    }
                    (op, operand) => Node::Unary(op, Box::new(operand)),
                });
            }
        }
        if let Some((type_name, length)) = self.cast_type() {
            self.at += length;
            let operand = self.unary()?;
            return Ok(Node::Cast(type_name, Box::new(operand)));
        }
        self.postfix()
    }

    /// A cast at the cursor: `(nt!_TOKEN *)`, `(unsigned char)`, with its
    /// length in tokens. A name in parentheses is a cast only when it names
    /// a module's type or a primitive, or is a pointer type, and an operand
    /// follows.
    fn cast_type(&self) -> Option<(String, usize)> {
        if !self.is_punct("(") {
            return None;
        }
        let mut words = Vec::new();
        let mut stars = 0;
        let mut length = 1;
        loop {
            match self.peek_at(length)? {
                Token::Name(name) if stars == 0 => words.push(name.clone()),
                Token::Punct("*") => stars += 1,
                Token::Punct(")") => break,
                _ => return None,
            }
            length += 1;
        }
        length += 1;
        let qualified = words.iter().any(|word| word.contains('!'));
        let primitive = words
            .iter()
            .all(|word| PRIMITIVE_TYPES.contains(&word.as_str()));
        if words.is_empty()
            || words.iter().any(|word| self.params.contains(word))
            || !(qualified || primitive || stars > 0)
        {
            return None;
        }
        let operand_follows = matches!(
            self.peek_at(length),
            Some(Token::Name(_) | Token::Int(_) | Token::Str(_))
                | Some(Token::Punct("(" | "*" | "&" | "-" | "~" | "!"))
        );
        operand_follows.then(|| {
            let mut name = words.join(" ");
            if stars > 0 {
                name.push(' ');
                name.push_str(&"*".repeat(stars));
            }
            (name, length)
        })
    }

    fn postfix(&mut self) -> Result<Node> {
        let mut node = self.primary()?;
        loop {
            if self.eat(".") {
                let name = self.name()?;
                if self.eat("(") {
                    let args = self.arguments()?;
                    node = Node::Call(Box::new(node), name, args);
                } else {
                    node = Node::Member(Box::new(node), name);
                }
            } else if self.eat("->") {
                node = Node::Arrow(Box::new(node), self.name()?);
            } else if self.eat("[") {
                let index = self.expression()?;
                self.expect("]")?;
                node = Node::Index(Box::new(node), Box::new(index));
            } else {
                return Ok(node);
            }
        }
    }

    fn arguments(&mut self) -> Result<Vec<Node>> {
        let mut args = Vec::new();
        if self.eat(")") {
            return Ok(args);
        }
        loop {
            args.push(self.expression()?);
            if self.eat(")") {
                return Ok(args);
            }
            self.expect(",")?;
        }
    }

    fn primary(&mut self) -> Result<Node> {
        let token = self
            .peek()
            .cloned()
            .ok_or_else(|| invalid("the expression ends early"))?;
        self.at += 1;
        Ok(match token {
            Token::Int(integer) => Node::Int(integer),
            Token::Str(text) => Node::Str(text),
            Token::Name(name) if name == "true" => Node::Bool(true),
            Token::Name(name) if name == "false" => Node::Bool(false),
            Token::Name(name) if name == "new" && self.is_punct("{") => {
                self.at += 1;
                self.object()?
            }
            Token::Name(name) => Node::Name(name),
            Token::Punct("(") => {
                let inner = self.expression()?;
                self.expect(")")?;
                inner
            }
            other => return Err(invalid(format!("unexpected {}", describe(&other)))),
        })
    }

    /// The fields of `new { Name = value, Id = p.Id }`. Each takes a name,
    /// as in WinDbg, which does not name a field after its path as C# does.
    fn object(&mut self) -> Result<Node> {
        let mut fields = Vec::new();
        if self.eat("}") {
            return Ok(Node::New(fields));
        }
        loop {
            let named = matches!(
                (self.peek(), self.peek_at(1)),
                (Some(Token::Name(_)), Some(Token::Punct("=")))
            );
            if !named {
                return Err(invalid(
                    "a field of new { } takes a name, as in new { Name = p.Name }",
                ));
            }
            let name = self.name()?;
            self.at += 1;
            fields.push((name, self.expression()?));
            if self.eat("}") {
                return Ok(Node::New(fields));
            }
            self.expect(",")?;
        }
    }
}

fn describe(token: &Token) -> String {
    match token {
        Token::Name(name) => format!("'{name}'"),
        Token::Int(integer) => format!("'{}'", integer.value),
        Token::Str(text) => format!("\"{text}\""),
        Token::Punct(punct) => format!("'{punct}'"),
    }
}

fn parse(text: &str) -> Result<Node> {
    let mut parser = Parser {
        tokens: tokenize(text)?,
        at: 0,
        params: Vec::new(),
    };
    let node = parser.expression()?;
    match parser.peek() {
        None => Ok(node),
        Some(token) => Err(invalid(format!(
            "unexpected {} after the expression",
            describe(token)
        ))),
    }
}

/// The lambda parameters bound while a query runs its lambda.
type Scope = Vec<(String, ModelValue)>;

struct Evaluator<'a> {
    target: &'a Target,
}

/// Evaluate the data model expression `text`.
pub fn evaluate(target: &Target, text: &str) -> Result<ModelValue> {
    let node = parse(text)?;
    Evaluator { target }.eval(&node, &mut Vec::new())
}

impl Evaluator<'_> {
    fn eval(&self, node: &Node, scope: &mut Scope) -> Result<ModelValue> {
        match node {
            Node::Int(integer) => Ok(ModelValue::Int(*integer)),
            Node::Str(text) => Ok(ModelValue::Text(text.clone())),
            Node::Bool(value) => Ok(ModelValue::Bool(*value)),
            Node::Name(name) => {
                if let Some((_, value)) = scope.iter().rev().find(|(param, _)| param == name) {
                    return Ok(value.clone());
                }
                if ROOTS.contains(&name.as_str()) {
                    return model::root(self.target, name);
                }
                // A symbol, a register, or a pseudo-register.
                Ok(ModelValue::Typed(name.clone()))
            }
            Node::Member(object, name) => {
                let object = self.eval(object, scope)?;
                self.member(&object, name)
            }
            Node::Arrow(object, name) => match self.eval(object, scope)? {
                ModelValue::Typed(expression) => {
                    Ok(ModelValue::Typed(format!("({expression})->{name}")))
                }
                _ => Err(invalid(format!(
                    "'->{name}' reads a typed pointer; a data model object takes '.{name}'"
                ))),
            },
            Node::Index(object, index) => {
                let object = self.eval(object, scope)?;
                let index = self.eval(index, scope)?;
                self.index(&object, &index)
            }
            Node::Call(object, method, args) => {
                let object = self.eval(object, scope)?;
                self.call(&object, method, args, scope)
            }
            Node::Unary(op, operand) => {
                let operand = self.eval(operand, scope)?;
                self.unary(op, operand)
            }
            Node::Binary(op, left, right) => self.binary(op, left, right, scope),
            Node::Conditional(condition, then, otherwise) => {
                let condition = self.eval(condition, scope)?;
                if self.truth(&condition)? {
                    self.eval(then, scope)
                } else {
                    self.eval(otherwise, scope)
                }
            }
            Node::Cast(type_name, operand) => match self.eval(operand, scope)? {
                ModelValue::Typed(expression) => {
                    // An array casts as its first element's address, as in
                    // C++: `(char *)p.ImageFileName`.
                    let array = matches!(
                        self.typed(&expression)?.type_data(),
                        Some(ParsedType::Array(..))
                    );
                    let operand = if array {
                        format!("&({expression})")
                    } else {
                        expression
                    };
                    Ok(ModelValue::Typed(format!("(({type_name})({operand}))")))
                }
                other => {
                    let value = self.number(&other)?.value;
                    Ok(ModelValue::Typed(format!(
                        "(({type_name}){:#x})",
                        value as u64
                    )))
                }
            },
            Node::New(fields) => Ok(ModelValue::Object(
                fields
                    .iter()
                    .map(|(name, value)| Ok((name.clone(), self.eval(value, scope)?)))
                    .collect::<Result<_>>()?,
            )),
            Node::Lambda(..) => Err(invalid(
                "a lambda is an argument of a query, such as .Where(p => ...)",
            )),
        }
    }

    /// The typed expression `expression`, evaluated.
    fn typed(&self, expression: &str) -> Result<ExprValue> {
        Expr::parse_with_radix(expression, NumberRadix::Decimal)?.evaluate(self.target)
    }

    /// `.name` of `object`: a model property, a string's `Length`, or a
    /// typed value's field, through a pointer as `dx` reads one.
    fn member(&self, object: &ModelValue, name: &str) -> Result<ModelValue> {
        match object {
            ModelValue::Typed(expression) => {
                let pointer = matches!(
                    self.typed(expression)?.type_data(),
                    Some(ParsedType::Pointer(_))
                );
                Ok(ModelValue::Typed(if pointer {
                    format!("({expression})->{name}")
                } else {
                    format!("({expression}).{name}")
                }))
            }
            ModelValue::ObjectHeader { header, .. }
                if !matches!(name, "ObjectName" | "UnderlyingObject") =>
            {
                Ok(ModelValue::Typed(format!(
                    "(*((nt!_OBJECT_HEADER *){:#x})).{name}",
                    header.0
                )))
            }
            _ if model::is_collection(object) => Err(invalid(format!(
                "a collection has no property {name}; take an element with [key] or .First(), \
                 or each element's with .Select(x => x.{name})"
            ))),
            _ => model::property(self.target, object, name),
        }
    }

    fn index(&self, object: &ModelValue, index: &ModelValue) -> Result<ModelValue> {
        let key = self.number(index)?.value;
        if let ModelValue::Typed(expression) = object {
            return Ok(ModelValue::Typed(format!("({expression})[{key}]")));
        }
        if !model::is_collection(object) {
            return Err(invalid("[ ] indexes a collection or a typed array"));
        }
        let key = u64::try_from(key).map_err(|_| invalid(format!("{key} is not a key")))?;
        model::elements(self.target, object)?
            .into_iter()
            .find(|(element_key, _)| *element_key == key)
            .map(|(_, element)| element)
            .ok_or_else(|| invalid(format!("the collection has no element [{key:#x}]")))
    }

    fn call(
        &self,
        object: &ModelValue,
        method: &str,
        args: &[Node],
        scope: &mut Scope,
    ) -> Result<ModelValue> {
        if model::is_collection(object) {
            let elements = model::elements(self.target, object)?;
            return self.query(elements, method, args, scope);
        }
        match object {
            ModelValue::Text(text) => self.string_method(text, method, args, scope),
            ModelValue::Collections if method == "FromListEntry" => self.list_entries(args, scope),
            ModelValue::Collections => Err(invalid(format!(
                "Debugger.Utility.Collections has FromListEntry, not {method}"
            ))),
            _ => Err(invalid(format!("this value has no method {method}"))),
        }
    }

    /// Run `lambda` on `element`.
    fn apply(&self, lambda: &Node, element: ModelValue, scope: &mut Scope) -> Result<ModelValue> {
        let Node::Lambda(param, body) = lambda else {
            return Err(invalid(
                "a query takes a lambda, such as .Where(p => p.Name == \"lsass.exe\")",
            ));
        };
        scope.push((param.clone(), element));
        let result = self.eval(body, scope);
        scope.pop();
        result
    }

    fn query(
        &self,
        elements: Vec<(u64, ModelValue)>,
        method: &str,
        args: &[Node],
        scope: &mut Scope,
    ) -> Result<ModelValue> {
        let lambda = args.first();
        let arity = |expected: &[usize]| {
            if expected.contains(&args.len()) {
                Ok(())
            } else {
                Err(invalid(format!(
                    ".{method}() takes {}",
                    match expected {
                        [0] => "no argument".to_string(),
                        [1] => "one argument".to_string(),
                        _ => "a lambda or nothing".to_string(),
                    }
                )))
            }
        };
        // Each element's result, with the key it keeps.
        let mut mapped =
            |elements: Vec<(u64, ModelValue)>| -> Result<Vec<(u64, ModelValue, ModelValue)>> {
                let lambda =
                    lambda.ok_or_else(|| invalid(format!(".{method}() takes a lambda")))?;
                elements
                    .into_iter()
                    .map(|(key, element)| {
                        let result = self
                            .apply(lambda, element.clone(), scope)
                            .map_err(|error| invalid(format!("[{key:#x}]: {}", message(&error))))?;
                        Ok((key, element, result))
                    })
                    .collect()
            };
        Ok(match method {
            "Where" => {
                arity(&[1])?;
                let mut kept = Vec::new();
                for (key, element, result) in mapped(elements)? {
                    if self.truth(&result)? {
                        kept.push((key, element));
                    }
                }
                ModelValue::List(kept)
            }
            "Select" => {
                arity(&[1])?;
                ModelValue::List(
                    mapped(elements)?
                        .into_iter()
                        .map(|(key, _, result)| (key, result))
                        .collect(),
                )
            }
            "SelectMany" => {
                arity(&[1])?;
                let mut flat = Vec::new();
                for (key, _, result) in mapped(elements)? {
                    if !model::is_collection(&result) {
                        return Err(invalid(format!(
                            "[{key:#x}]: .SelectMany() takes a lambda that gives a collection"
                        )));
                    }
                    flat.extend(model::elements(self.target, &result)?);
                }
                ModelValue::List(
                    flat.into_iter()
                        .enumerate()
                        .map(|(index, (_, value))| (index as u64, value))
                        .collect(),
                )
            }
            "First" | "Last" => {
                arity(&[0, 1])?;
                let candidates = if lambda.is_some() {
                    let mut kept = Vec::new();
                    for (key, element, result) in mapped(elements)? {
                        if self.truth(&result)? {
                            kept.push((key, element));
                        }
                    }
                    kept
                } else {
                    elements
                };
                let found = if method == "First" {
                    candidates.into_iter().next()
                } else {
                    candidates.into_iter().last()
                };
                found
                    .map(|(_, element)| element)
                    .ok_or_else(|| invalid(format!(".{method}() found no element")))?
            }
            "Any" | "All" | "Count" => {
                arity(&[0, 1])?;
                let matches = if lambda.is_some() {
                    let mut matches = 0;
                    for (_, _, result) in mapped(elements.clone())? {
                        matches += usize::from(self.truth(&result)?);
                    }
                    matches
                } else if method == "All" {
                    return Err(invalid(".All() takes a lambda"));
                } else {
                    elements.len()
                };
                match method {
                    "Any" => ModelValue::Bool(matches > 0),
                    "All" => ModelValue::Bool(matches == elements.len()),
                    _ => ModelValue::unsigned(matches as u64),
                }
            }
            "OrderBy" | "OrderByDescending" => {
                arity(&[1])?;
                let mut keyed = mapped(elements)?;
                let mut error = None;
                let descending = method == "OrderByDescending";
                keyed.sort_by(|(_, _, left), (_, _, right)| {
                    let order = self.compare(left, right).unwrap_or_else(|failure| {
                        error.get_or_insert(failure);
                        Ordering::Equal
                    });
                    if descending { order.reverse() } else { order }
                });
                if let Some(error) = error {
                    return Err(error);
                }
                // The elements keep their keys in their new order.
                ModelValue::List(
                    keyed
                        .into_iter()
                        .map(|(key, element, _)| (key, element))
                        .collect(),
                )
            }
            "Take" | "Skip" => {
                arity(&[1])?;
                let count = self.eval(&args[0], scope)?;
                let count = self.number(&count)?.value;
                let count = usize::try_from(count.max(0)).unwrap_or(usize::MAX);
                ModelValue::List(if method == "Take" {
                    elements.into_iter().take(count).collect()
                } else {
                    elements.into_iter().skip(count).collect()
                })
            }
            _ => {
                return Err(invalid(format!(
                    "{method} is not a query dx evaluates; it evaluates {QUERIES}"
                )));
            }
        })
    }

    fn string_method(
        &self,
        text: &str,
        method: &str,
        args: &[Node],
        scope: &mut Scope,
    ) -> Result<ModelValue> {
        let argument = |scope: &mut Scope| -> Result<String> {
            match args {
                [arg] => match self.eval(arg, scope)? {
                    ModelValue::Text(text) => Ok(text),
                    _ => Err(invalid(format!(".{method}() takes a string"))),
                },
                _ => Err(invalid(format!(".{method}() takes one string"))),
            }
        };
        Ok(match method {
            "Contains" => ModelValue::Bool(text.contains(&argument(scope)?)),
            "StartsWith" => ModelValue::Bool(text.starts_with(&argument(scope)?)),
            "EndsWith" => ModelValue::Bool(text.ends_with(&argument(scope)?)),
            "ToLower" if args.is_empty() => ModelValue::Text(text.to_lowercase()),
            "ToUpper" if args.is_empty() => ModelValue::Text(text.to_uppercase()),
            _ => {
                return Err(invalid(format!(
                    "a string has no method {method}; it has {STRING_METHODS}"
                )));
            }
        })
    }

    /// `FromListEntry(head, "nt!_EPROCESS", "ActiveProcessLinks")`: the
    /// records on the `_LIST_ENTRY` list at `head`, each the type named,
    /// whose field the entry is.
    fn list_entries(&self, args: &[Node], scope: &mut Scope) -> Result<ModelValue> {
        let usage = || {
            invalid(
                "FromListEntry takes the list head, the record's type, and its link field, \
                 as in FromListEntry(*(nt!_LIST_ENTRY *)&nt!PsActiveProcessHead, \
                 \"nt!_EPROCESS\", \"ActiveProcessLinks\")",
            )
        };
        let [head, record, field] = args else {
            return Err(usage());
        };
        let (ModelValue::Text(record), ModelValue::Text(field)) =
            (self.eval(record, scope)?, self.eval(field, scope)?)
        else {
            return Err(usage());
        };
        let head = match self.eval(head, scope)? {
            ModelValue::Typed(expression) => {
                let value = self.typed(&expression)?;
                match value {
                    ExprValue::Raw {
                        address: Some(address),
                        ..
                    } => address,
                    ExprValue::Raw { value, .. } => value,
                    other => other.address()?,
                }
            }
            other => VirtAddr(self.number(&other)?.value as u64),
        };
        // The link's offset in the record, as `&((T *)0)->Field` reads it.
        let offset = self
            .typed(&format!("&((({record} *)0)->{field})"))?
            .scalar(self.target)?
            .0;
        let types = self.target.types_in(self.target.current_dtb());
        let flink = |entry: VirtAddr| -> Result<VirtAddr> {
            types.struct_at("_LIST_ENTRY", entry)?.read_pointer("Flink")
        };
        let mut seen = HashSet::new();
        let mut records = Vec::new();
        let mut entry = flink(head)?;
        while entry != head && !entry.is_zero() {
            if !seen.insert(entry) || records.len() == MAX_LIST_ENTRIES {
                break;
            }
            let address = entry.0.wrapping_sub(offset);
            records.push((
                records.len() as u64,
                ModelValue::Typed(format!("(*(({record} *){address:#x}))")),
            ));
            entry = flink(entry)?;
        }
        Ok(ModelValue::List(records))
    }

    /// A number from an integer, a Boolean, or a typed scalar, typed as C
    /// types it: a typed value keeps its sign, and takes 64 bits when it is
    /// wider than an `int`.
    fn number(&self, value: &ModelValue) -> Result<Integer> {
        match value {
            ModelValue::Int(integer) => Ok(*integer),
            ModelValue::Bool(value) => Ok(Integer::new(i128::from(*value), false, false)),
            ModelValue::Typed(expression) => {
                let value = self.typed(expression)?;
                let raw = value.scalar(self.target)?.0;
                let signed = match value.type_data() {
                    Some(ParsedType::Primitive(name)) => is_signed_primitive(name),
                    _ => false,
                };
                let size = value.byte_size().unwrap_or(8).clamp(1, 8);
                let raw = if signed {
                    let shift = 64 - size * 8;
                    i128::from(((raw << shift) as i64) >> shift)
                } else {
                    i128::from(raw)
                };
                Ok(Integer::new(raw, !signed, size > 4))
            }
            _ => Err(invalid("this value is not a number")),
        }
    }

    fn truth(&self, value: &ModelValue) -> Result<bool> {
        match value {
            ModelValue::Bool(value) => Ok(*value),
            other => Ok(self.number(other)?.value != 0),
        }
    }

    fn unary(&self, op: &str, operand: ModelValue) -> Result<ModelValue> {
        if let ModelValue::Typed(expression) = &operand
            && matches!(op, "*" | "&")
        {
            return Ok(ModelValue::Typed(format!("{op}({expression})")));
        }
        if op == "!" {
            return Ok(ModelValue::Bool(!self.truth(&operand)?));
        }
        let integer = self.number(&operand)?;
        let result = match op {
            "-" => -integer.value,
            "~" => !integer.value,
            _ => {
                return Err(invalid(format!(
                    "'{op}' reads a typed value, not a data model one"
                )));
            }
        };
        Ok(ModelValue::Int(Integer::new(
            result,
            integer.unsigned,
            integer.wide,
        )))
    }

    fn binary(&self, op: &str, left: &Node, right: &Node, scope: &mut Scope) -> Result<ModelValue> {
        if matches!(op, "&&" | "||") {
            let left = self.eval(left, scope)?;
            let left = self.truth(&left)?;
            if (op == "&&") != left {
                return Ok(ModelValue::Bool(left));
            }
            let right = self.eval(right, scope)?;
            return Ok(ModelValue::Bool(self.truth(&right)?));
        }
        let left = self.eval(left, scope)?;
        let right = self.eval(right, scope)?;
        // As in WinDbg, a string is never equal to anything but a string.
        if matches!(op, "==" | "!=")
            && matches!(left, ModelValue::Text(_)) != matches!(right, ModelValue::Text(_))
        {
            return Ok(ModelValue::Bool(op == "!="));
        }
        if matches!(op, "==" | "!=" | "<" | ">" | "<=" | ">=") {
            let order = self.compare(&left, &right)?;
            return Ok(ModelValue::Bool(match op {
                "==" => order == Ordering::Equal,
                "!=" => order != Ordering::Equal,
                "<" => order == Ordering::Less,
                ">" => order == Ordering::Greater,
                "<=" => order != Ordering::Greater,
                _ => order != Ordering::Less,
            }));
        }
        if op == "+"
            && let (ModelValue::Text(left), ModelValue::Text(right)) = (&left, &right)
        {
            return Ok(ModelValue::Text(format!("{left}{right}")));
        }
        let left = self.number(&left)?;
        let right = self.number(&right)?;
        let (a, b) = (left.value, right.value);
        let shift = || u32::try_from(b).ok().filter(|bits| *bits < 64);
        // A shift keeps its left operand's type; anything else is unsigned
        // when either side is, as WinDbg's `(unsigned char)x & 0xF` is, and
        // 64 bits when either side is.
        let (unsigned, wide) = if matches!(op, "<<" | ">>") {
            (left.unsigned, left.wide)
        } else {
            (left.unsigned || right.unsigned, left.wide || right.wide)
        };
        let value = match op {
            "+" => a + b,
            "-" => a - b,
            "*" => a.wrapping_mul(b),
            "/" | "%" if b == 0 => return Err(invalid("division by zero")),
            "/" => a / b,
            "%" => a % b,
            "&" => a & b,
            "|" => a | b,
            "^" => a ^ b,
            "<<" => a << shift().ok_or_else(|| invalid("a shift takes 0 to 63 bits"))?,
            ">>" => a >> shift().ok_or_else(|| invalid("a shift takes 0 to 63 bits"))?,
            _ => return Err(invalid(format!("'{op}' is not an operator dx evaluates"))),
        };
        Ok(ModelValue::Int(Integer::new(value, unsigned, wide)))
    }

    /// The order of two values: strings by their characters, and numbers
    /// by value, as unsigned ones when either is, so `-1 < 0u` is false as
    /// in C.
    fn compare(&self, left: &ModelValue, right: &ModelValue) -> Result<Ordering> {
        match (left, right) {
            (ModelValue::Text(left), ModelValue::Text(right)) => Ok(left.cmp(right)),
            (ModelValue::Text(_), _) | (_, ModelValue::Text(_)) => {
                Err(invalid("a string compares only with a string"))
            }
            _ => {
                let (left, right) = (self.number(left)?, self.number(right)?);
                if left.unsigned || right.unsigned {
                    let wide = left.wide || right.wide;
                    let as_unsigned =
                        |integer: Integer| Integer::new(integer.value, true, wide).value;
                    Ok(as_unsigned(left).cmp(&as_unsigned(right)))
                } else {
                    Ok(left.value.cmp(&right.value))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(text: &str) -> Vec<Token> {
        tokenize(text).unwrap()
    }

    /// `nt!PsActiveProcessHead` and `@$curprocess` are one name each, while a
    /// `!` before `=` or at the start of an operand is an operator.
    #[test]
    fn names_take_module_qualifiers_but_not_operators() {
        assert_eq!(
            tokens("nt!PsActiveProcessHead != !@$curprocess"),
            [
                Token::Name("nt!PsActiveProcessHead".into()),
                Token::Punct("!="),
                Token::Punct("!"),
                Token::Name("@$curprocess".into()),
            ]
        );
        assert_eq!(
            tokens("0xfffff801`00000000 10 \"a\\\"b\""),
            [
                Token::Int(Integer::new(0xffff_f801_0000_0000, false, true)),
                Token::Int(Integer::new(10, false, false)),
                Token::Str("a\"b".into()),
            ]
        );
    }

    /// Only an expression that reads a model root or builds an object goes
    /// to the data model; a typed expression keeps the typed path.
    #[test]
    fn queries_are_told_from_typed_expressions() {
        assert!(is_query("@$cursession.Processes.Where(p => p.Id == 4)"));
        assert!(is_query(
            "((nt!_TOKEN*)(@$curthread.KernelObject.ClientSecurity.ImpersonationToken & ~0xF))->AuthenticationId"
        ));
        assert!(is_query("new { A = 1 }"));
        assert!(!is_query("((nt!_EPROCESS*)@rcx)->UniqueProcessId"));
        assert!(!is_query("DebuggerData"));
    }

    fn parsed(text: &str) -> String {
        format!("{:?}", parse(text).unwrap())
    }

    /// `(p)` inside a lambda over `p` is a parenthesized name, while
    /// `(nt!_TOKEN *)` and `(unsigned char)` are casts.
    #[test]
    fn casts_are_told_from_parentheses() {
        assert!(parsed("(nt!_TOKEN *)x").starts_with("Cast(\"nt!_TOKEN *\""));
        assert!(parsed("(unsigned char)x").starts_with("Cast(\"unsigned char\""));
        assert!(parsed("p => (p) * 2").contains("Binary(\"*\", Name(\"p\")"));
        // A plain name in parentheses is not a type.
        assert!(parsed("(x) - 1").starts_with("Binary(\"-\""));
    }

    /// Precedence follows C# and C++: `==` binds tighter than `&`, which
    /// binds tighter than `&&`, and a member call binds tightest.
    #[test]
    fn operators_bind_as_in_csharp() {
        assert_eq!(parsed("a & 0xF == 3 && b"), parsed("(a & (0xF == 3)) && b"));
        assert_eq!(parsed("a + 2 * 3 << 1"), parsed("(a + (2 * 3)) << 1"));
        assert!(
            parsed("p.Name.ToLower().Contains(\"svc\")")
                .starts_with("Call(Call(Member(Name(\"p\"), \"Name\"), \"ToLower\", [])")
        );
        assert!(parsed("new { Name = p.Name, Pid = p.Id }").starts_with("New([(\"Name\""));
        // WinDbg names no field after its path, as C# does.
        assert!(parse("new { p.Name }").is_err());
    }

    /// A lambda's parameter may be written in parentheses, and a lambda is
    /// a whole argument, its body running to the closing parenthesis.
    #[test]
    fn lambdas_take_their_whole_argument() {
        assert!(
            parsed("x.Where((p) => p.Id > 4 && p.Id < 8)")
                .starts_with("Call(Name(\"x\"), \"Where\", [Lambda(\"p\", Binary(\"&&\"")
        );
        assert!(parse("x.Where(p => )").is_err());
        assert!(parse("new { 1 }").is_err());
    }

    fn fields(text: &str) -> Vec<(String, String)> {
        let session = crate::session::session_over_memory(0x1000, &[0; 0x10]);
        let ModelValue::Object(fields) = evaluate(&session.target, text).unwrap() else {
            panic!("{text} is not an object");
        };
        fields
            .into_iter()
            .map(|(name, value)| {
                let text = match value {
                    ModelValue::Int(integer) => integer.text(false),
                    ModelValue::Text(text) => format!("{text:?}"),
                    ModelValue::Bool(value) => value.to_string(),
                    _ => "?".to_string(),
                };
                (name, text)
            })
            .collect()
    }

    /// Integers keep the types WinDbg's `dx` gives them, each checked
    /// against it: a literal is an `int`, or an `__int64` when it does not
    /// fit one, and wraps as one; `u` makes it unsigned; an unsigned
    /// operand makes the result unsigned, so `-1 < 0u` is false; and `~0xF`
    /// masks an address. A string is never equal to a number, and `+`
    /// joins strings.
    #[test]
    fn operators_keep_c_integer_types_and_compare_strings() {
        let pairs = |list: &[(&str, &str)]| {
            list.iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            fields(
                "new { A = 10 + 0x10, B = 0xffff828eb87d82dfu & ~0xF, C = 1 - 2, D = 0u - 1, \
                 E = 5 / 2, F = 0x7fffffff + 1, G = 0xffffffffffffffff, H = 0xffffffff, \
                 I = -1 < 0u }"
            ),
            pairs(&[
                ("A", "26"),
                ("B", "0xffff828eb87d82d0"),
                ("C", "-1"),
                ("D", "0xffffffff"),
                ("E", "2"),
                ("F", "-2147483648"),
                ("G", "-1"),
                ("H", "4294967295"),
                ("I", "false"),
            ])
        );
        assert_eq!(
            fields(
                "new { S = \"lsass.exe\".ToUpper() + \"!\", T = \"a\" < \"b\" && 2 > 1 ? \"yes\" : \"no\", \
                 L = \"explorer\".Length, N = !(\"x\".StartsWith(\"x\")), Q = \"5\" == 5 }"
            ),
            pairs(&[
                ("S", "\"LSASS.EXE!\""),
                ("T", "\"yes\""),
                ("L", "0x8"),
                ("N", "false"),
                ("Q", "false"),
            ])
        );
        let session = crate::session::session_over_memory(0x1000, &[0; 0x10]);
        assert!(evaluate(&session.target, "new { A = 1 / 0 }").is_err());
        assert!(evaluate(&session.target, "new { A = \"x\" < 1 }").is_err());
    }
}
