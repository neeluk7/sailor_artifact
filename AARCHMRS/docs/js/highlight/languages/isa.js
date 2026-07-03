function language_isa() {
    var config = {
        keywords: [
            "instruction_sets",
            "groups",
            "instructions",
            "in",
            "alias",
            "properties",
            "dict",
            "with",
            "extends",
        ],
        contains: [
            {
                scope: 'string',
                begin: '"',
                end: '"'
            },
            hljs.COMMENT(
                "#",
                "\\n"
            ),
        ]
    };
    return config;
}
hljs.registerLanguage(
    "isa",
    language_isa
)