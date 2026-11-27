{
    "targets": [
        {
            "target_name": "mcrypt",
            'dependencies': [
                'lib/libmcrypt/libmcrypt.gyp:libmcrypt',
            ],
            "sources": [
                "src/mcrypt.cc"
            ],
            "include_dirs": [
                "lib/libmcrypt/include/",
                "<!(node -e \"require('nan')\")"
            ],
            "conditions": [
                ["OS=='win'", {
                    # The Windows releases of Node 26 are built with clang and
                    # thin LTO, and common.gypi hands the options for that to
                    # every addon: -flto=thin and /opt:lldltojobs=N. Addons
                    # are built with MSVC. Its compiler ignores the first with
                    # a warning, and its linker stops at the second with
                    # LNK1117.
                    #
                    # node-gyp 13 switches the options off. The node-gyp that
                    # npm brings along in Node 26 is 12.4.0 and does not, and
                    # that is the one "npm install" uses. So the options are
                    # taken out here, by pattern because N varies.
                    "msvs_settings": {
                        "VCCLCompilerTool": {
                            "AdditionalOptions/": [["exclude", "^-flto"]]
                        },
                        "VCLibrarianTool": {
                            "AdditionalOptions/": [["exclude", "^-flto"]]
                        },
                        "VCLinkerTool": {
                            "AdditionalOptions/": [
                                ["exclude", "^-flto"],
                                ["exclude", "^/opt:lldltojobs"]
                            ]
                        }
                    }
                }]
            ]
        }
    ]
}
