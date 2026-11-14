# Translation Process

Nito Core supports multiple Qt interface translations. Translation files live
under `src/qt/locale/`.

## Developer Workflow

Do not edit compiled `.qm` files directly. When source strings change, update
the English translation source and regenerate translation files through the
project tooling.

```bash
cd src
make translate
```

Use `tr()` for Qt strings:

```cpp
QToolBar* toolbar = addToolBar(tr("Tabs toolbar"));
```

For general code changes, avoid committing translation churn unless the change
intentionally updates user-facing strings. Translation refreshes should be
grouped into dedicated commits when possible.

## Source File Naming

Translation source files use one of these forms:

- `nito_xx.ts`
- `nito_xx_YY.ts`

The English source file is `src/qt/locale/nito_en.ts`.

Compiled translation resources use `.qm` files and are listed in
`src/qt/nito_locale.qrc`.

## Plurals

When a new pluralized string is added:

1. Open `nito_en.ts` in Qt Linguist.
2. Search for `%n`.
3. Fill both singular and plural English forms.
4. Mark each entry as done.
5. Save the file and rebuild translations.

## External Translation Service

If an external translation platform is configured for a release cycle, its
project URL and sync procedure should be documented in that release branch.
Do not leave stale platform links in the public documentation.
