// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2024 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/uritests.h>

#include <chainparams.h>
#include <private/private_address.h>
#include <qt/guiutil.h>
#include <qt/nitoaddressvalidator.h>
#include <qt/walletmodel.h>

#include <array>

#include <QUrl>

void URITests::uriTests()
{
    {
        std::array<unsigned char, NITO_ORCHARD_RAW_ADDRESS_SIZE> raw_private{};
        raw_private.fill(0x42);
        QString private_address = QString::fromStdString(wallet::EncodeNitoPrivateAddress(raw_private, Params()));
        int pos = 0;
        NitoAddressCheckValidator validator(nullptr);
        QVERIFY(validator.validate(private_address, pos) == QValidator::Acceptable);
        private_address.replace(private_address.size() - 1, 1, private_address.endsWith("q") ? "p" : "q");
        QVERIFY(validator.validate(private_address, pos) == QValidator::Invalid);
    }

    SendCoinsRecipient rv;
    QUrl uri;
    uri.setUrl(QString("nito:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?req-dontexist="));
    QVERIFY(!GUIUtil::parseNitoURI(uri, &rv));

    uri.setUrl(QString("nito:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?dontexist="));
    QVERIFY(GUIUtil::parseNitoURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("nito:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?label=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseNitoURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString("Wikipedia Example Address"));
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("nito:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=0.001"));
    QVERIFY(GUIUtil::parseNitoURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100000);

    uri.setUrl(QString("nito:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=1.001"));
    QVERIFY(GUIUtil::parseNitoURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100100000);

    uri.setUrl(QString("nito:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=100&label=Wikipedia Example"));
    QVERIFY(GUIUtil::parseNitoURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.amount == 10000000000LL);
    QVERIFY(rv.label == QString("Wikipedia Example"));

    uri.setUrl(QString("nito:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?message=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseNitoURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());

    QVERIFY(GUIUtil::parseNitoURI("nito:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?message=Wikipedia Example Address", &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());

    uri.setUrl(QString("nito:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?req-message=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseNitoURI(uri, &rv));

    // Commas in amounts are not allowed.
    uri.setUrl(QString("nito:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=1,000&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseNitoURI(uri, &rv));

    uri.setUrl(QString("nito:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=1,000.0&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseNitoURI(uri, &rv));

    // There are two amount specifications. The last value wins.
    uri.setUrl(QString("nito:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=100&amount=200&label=Wikipedia Example"));
    QVERIFY(GUIUtil::parseNitoURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.amount == 20000000000LL);
    QVERIFY(rv.label == QString("Wikipedia Example"));

    // The first amount value is correct. However, the second amount value is not valid. Hence, the URI is not valid.
    uri.setUrl(QString("nito:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=100&amount=1,000&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseNitoURI(uri, &rv));

    // Test label containing a question mark ('?').
    uri.setUrl(QString("nito:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=100&label=?"));
    QVERIFY(GUIUtil::parseNitoURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.amount == 10000000000LL);
    QVERIFY(rv.label == QString("?"));

    // Escape sequences are not supported.
    uri.setUrl(QString("nito:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=100&label=%3F"));
    QVERIFY(GUIUtil::parseNitoURI(uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.amount == 10000000000LL);
    QVERIFY(rv.label == QString("%3F"));
}
