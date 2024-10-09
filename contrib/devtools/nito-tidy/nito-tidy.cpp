// Copyright (c) 2023 Bitcoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "logprintf.h"

#include <clang-tidy/ClangTidyModule.h>
#include <clang-tidy/ClangTidyModuleRegistry.h>

class NitoModule final : public clang::tidy::ClangTidyModule
{
public:
    void addCheckFactories(clang::tidy::ClangTidyCheckFactories& CheckFactories) override
    {
        CheckFactories.registerCheck<nito::LogPrintfCheck>("nito-unterminated-logprintf");
    }
};

static clang::tidy::ClangTidyModuleRegistry::Add<NitoModule>
    X("nito-module", "Adds nito checks.");

volatile int NitoModuleAnchorSource = 0;
