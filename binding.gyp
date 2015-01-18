{
    "targets": [
        {
            "target_name": "mcrypt",
            "sources": [
                "src/mcrypt.cc"
            ],
            "include_dirs": [
                "/usr/include/",
                "/opt/local/include/"
            ],
            "link_settings": {
                "libraries": [
                    "-lmcrypt"
                ]
            }
        }
    ]
}
