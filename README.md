## ELF Loader Bootstrapping Utility

This tool is designed to make loading arbitrary ELF files from a loader stub easier.

The usage for this is:
`exploit -> loader -> bootstrapper (this utility) -> arbitrary ELF`

Loosly (more or less) based on the [article](https://fasterthanli.me/series/making-our-own-executable-packer/) from fasterthanlime - they didn't seem to post their code.

Going to skip their packing stuff, and try to make the ELF parsing lib `no_std` - making it easier to use in a PIC environment (hopefully)
