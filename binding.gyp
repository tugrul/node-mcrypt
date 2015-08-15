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
                "<!(node -e \"require('nan')\")"
            ]
        }
    ]
}
