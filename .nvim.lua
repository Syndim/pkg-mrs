require("features").setup({
    plugin = {
        code_companion = {
            enabled = true,
            adapters = {
                copilot = {
                    model = "claude-sonnet-4.5"
                }
            },
            proxy = 'http://127.0.0.1:7890'
        },
        sidekick = {
            enabled = true,
        }
    },
    editor = {
        format_on_save = true,
    },
})