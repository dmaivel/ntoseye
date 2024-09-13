#include <atomic>
#include <llvm/ADT/STLExtras.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/DebugInfo/CodeView/CVSymbolVisitor.h>
#include <llvm/DebugInfo/CodeView/CVTypeVisitor.h>
#include <llvm/DebugInfo/CodeView/DebugChecksumsSubsection.h>
#include <llvm/DebugInfo/CodeView/DebugCrossExSubsection.h>
#include <llvm/DebugInfo/CodeView/DebugCrossImpSubsection.h>
#include <llvm/DebugInfo/CodeView/DebugFrameDataSubsection.h>
#include <llvm/DebugInfo/CodeView/DebugInlineeLinesSubsection.h>
#include <llvm/DebugInfo/CodeView/DebugLinesSubsection.h>
#include <llvm/DebugInfo/CodeView/DebugStringTableSubsection.h>
#include <llvm/DebugInfo/CodeView/DebugSymbolsSubsection.h>
#include <llvm/DebugInfo/CodeView/Formatters.h>
#include <llvm/DebugInfo/CodeView/LazyRandomTypeCollection.h>
#include <llvm/DebugInfo/CodeView/Line.h>
#include <llvm/DebugInfo/CodeView/SymbolDeserializer.h>
#include <llvm/DebugInfo/CodeView/SymbolVisitorCallbackPipeline.h>
#include <llvm/DebugInfo/CodeView/SymbolVisitorCallbacks.h>
#include <llvm/DebugInfo/CodeView/TypeHashing.h>
#include <llvm/DebugInfo/CodeView/TypeIndexDiscovery.h>
#include <llvm/DebugInfo/MSF/MappedBlockStream.h>
#include <llvm/DebugInfo/PDB/Native/DbiModuleDescriptor.h>
#include <llvm/DebugInfo/PDB/Native/DbiStream.h>
#include <llvm/DebugInfo/PDB/Native/FormatUtil.h>
#include <llvm/DebugInfo/PDB/Native/GlobalsStream.h>
#include <llvm/DebugInfo/PDB/Native/ISectionContribVisitor.h>
#include <llvm/DebugInfo/PDB/Native/InputFile.h>
#include <llvm/DebugInfo/PDB/Native/ModuleDebugStream.h>
#include <llvm/DebugInfo/PDB/Native/PDBFile.h>
#include <llvm/DebugInfo/PDB/Native/PublicsStream.h>
#include <llvm/DebugInfo/PDB/Native/RawError.h>
#include <llvm/DebugInfo/PDB/Native/SymbolStream.h>
#include <llvm/DebugInfo/PDB/Native/TpiHashing.h>
#include <llvm/DebugInfo/PDB/Native/TpiStream.h>
#include <llvm/DebugInfo/CodeView/SymbolRecord.h>
#include <llvm/DebugInfo/PDB/IPDBSession.h>
#include <llvm/DebugInfo/PDB/Native/LinePrinter.h>
#include <llvm/DebugInfo/PDB/PDB.h>
#include <llvm/DebugInfo/PDB/PDBSymbolExe.h>
#include <llvm/DebugInfo/PDB/PDBSymbolTypeFunctionSig.h>
#include <llvm/DebugInfo/PDB/IPDBLineNumber.h>
#include <llvm/DebugInfo/PDB/PDBSymbolFunc.h>
#include <llvm/DebugInfo/PDB/PDBSymbolTypeUDT.h>
#include <llvm/DebugInfo/PDB/PDBSymbolData.h>
#include <llvm/DebugInfo/PDB/Native/NativeSession.h>
#include <llvm/DebugInfo/PDB/Native/InfoStream.h>
#include <llvm/DebugInfo/PDB/Native/DbiStream.h>
#include <llvm/DebugInfo/PDB/Native/SymbolStream.h>
#include <llvm/DebugInfo/PDB/Native/NativeFunctionSymbol.h>
#include <llvm/DebugInfo/PDB/Native/NativePublicSymbol.h>
#include <llvm/Object/COFF.h>
#include <llvm/Object/Error.h>

#include "pdb.hpp"
#include "cmd.hpp"
#include "config.hpp"
#include "curl.hpp"
#include "guest.hpp"
#include "log.hpp"
#include "util.hpp"

#include <format>
#include <filesystem>
#include <print>
#include <algorithm>
#include <execution>

using namespace llvm::codeview;

std::vector<pdb::symbol> symbols;

static std::string get_pdb_path_from_storage(pdb::metadata &metadata)
{
    auto download_destination_directory = std::format("{}/symbols", config::get_storage_directory());
    std::filesystem::create_directories(download_destination_directory);

    auto target_file_path = std::format("{}/{}.{}", download_destination_directory, metadata.filename, metadata.id);

    bool does_exact_symbol_file_not_exist = true;
    std::ranges::all_of(std::filesystem::directory_iterator(download_destination_directory),
        [&](auto dir_entry) {
            if (!dir_entry.is_regular_file())
                return true;

            does_exact_symbol_file_not_exist = dir_entry.path() != target_file_path.c_str();
            return does_exact_symbol_file_not_exist;
        }
    );

    if (does_exact_symbol_file_not_exist)
        if (!curl::attempt_file_download(target_file_path, metadata.url))
            return {};

    return target_file_path;
}

static bool attempt_get_symbols(pdb::metadata metadata, const std::string &prefix, int attempts = 0)
{
    if (attempts >= pdb::max_download_attempts) {
        // out::warn("exceeded max download attempts on pdb, skipping...\n");
        return false;
    }

    if (!metadata.valid())
        return false;

    auto path = get_pdb_path_from_storage(metadata);
    if (path.empty())
        return false;

    auto file = llvm::pdb::InputFile::open(path);
    if (!file) {
        std::filesystem::remove(path);
        // std::println("Failed to open pdb ({}), removed and retrying...", toString(file.takeError()));
        return attempt_get_symbols(metadata, prefix, attempts + 1);
    }

    if (!file->pdb().hasPDBPublicsStream() || !file->pdb().hasPDBSymbolStream()) {
        // std::println("PDB has no publics or symbol streams");
        return false;
    }

    auto expected_symbol_stream = file->pdb().getPDBSymbolStream();
    if (!expected_symbol_stream) {
        // std::println("Failed to get symbol stream ({})", toString(expected_symbol_stream.takeError()));
        return false;
    }

    auto &symbol_stream = *expected_symbol_stream;

    llvm::for_each(file->pdb().getPDBPublicsStream()->getPublicsTable(), [&](auto offset){
        auto cv_sym = symbol_stream.readRecord(offset);
        if (cv_sym.kind() == SymbolKind::S_PUB32) {
            auto public_symbol = cantFail(SymbolDeserializer::deserializeAs<PublicSym32>(cv_sym));

            symbols.push_back({
                .name = !prefix.empty() ? std::format("{}!{}", prefix, public_symbol.Name.str()) : public_symbol.Name.str(),
                .offset = public_symbol.Offset,
                .type = public_symbol.Flags == PublicSymFlags::None ? pdb::symbol::sym_type::data : pdb::symbol::sym_type::function
            });
        }
    });

    return true;
}

void pdb::load(mem::process &process, process_priv priv)
{
    static auto prompt_message = "Current process/modules may have undownloaded symbols. Would you like to download them? (y/[n]): ";

    std::atomic_int success_count = 0, fail_count = 0;

    auto print_download_count = [&](const std::string &pdb) {
        out::clear();
        std::print("Downloading '{}'... ({} succeeded, {} failed)", pdb.size() < 32 ? pdb : std::format("{}...", pdb.substr(0, 32)), out::green(success_count), out::red(fail_count));
        std::fflush(stdout);
    };

    auto update_count = [&](bool status) {
        if (status)
            success_count++;
        else
            fail_count++;
    };
    
    // auto metadata = util::get_pdb_metadata(process);
    // if (metadata.valid()) {
    //     auto should_download = cmd::read_yes_no(prompt_message);
    //     if (!should_download)
    //         return;

    //     print_download_count(metadata.filename);
    //     update_count(attempt_get_symbols(metadata, priv == process_priv::kernel ? "nt" : ""));
    //     asked = true;
    // }

    std::vector<util::module> modules;
    if (priv == process_priv::kernel)
        modules = guest::get_kernel_modules();
    else
        modules = util::get_modules(process);

    auto should_download = cmd::read_yes_no(prompt_message);
    if (!should_download)
        return;

    for (auto &x : modules) {
        mem::process module_disguised_as_process = process;
        module_disguised_as_process.dos_header = nullptr;
        module_disguised_as_process.nt_headers = nullptr;
        module_disguised_as_process.base_address = x.base_address;

        auto metadata = util::get_pdb_metadata(module_disguised_as_process);
        if (!metadata.valid())
            continue;

        print_download_count(metadata.filename);
        update_count(attempt_get_symbols(metadata, x.name.substr(0, x.name.find("."))));
    }

    out::clear();
    std::println("Downloaded symbols ({} succeeded, {} failed)", out::green(success_count), out::red(fail_count));
}

std::optional<pdb::symbol> pdb::get(const std::string &str)
{
    auto str_modified = util::string_replace(str, "nt!", "ntoskrnl!");

    auto sym = std::find_if(symbols.begin(), symbols.end(), [str_modified](const pdb::symbol &sym) {
        return sym.name.contains(str_modified);
    });

    if (sym != symbols.end())
        return *sym;
    return {};
}

std::vector<pdb::symbol> pdb::get_all()
{
    return symbols;
}