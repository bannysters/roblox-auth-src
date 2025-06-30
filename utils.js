const { EmbedBuilder, ActionRowBuilder, ButtonBuilder } = require("discord.js");

module.exports = {
    make_fuckass_embed({ title, description = "No description provided.", color = "#0099ff", fields = [], buttons = [] }) {
        if (!title || typeof title !== "string") {
            throw new Error("Invalid or missing 'title' parameter for embed.");
        }

        if (typeof description !== "string") {
            throw new Error("Invalid 'description' parameter for embed.");
        }

        const embed = new EmbedBuilder()
            .setTitle(title)
            .setDescription(description)
            .setColor(color);

        if (fields.length > 0) {
            embed.addFields(fields);
        }

        const components = [];
        if (buttons.length > 0) {
            const actionRow = new ActionRowBuilder();
            buttons.forEach((button) => {
                actionRow.addComponents(
                    new ButtonBuilder()
                        .setLabel(button.label)
                        .setStyle(button.style) 
                        .setCustomId(button.customId)
                );
            });
            components.push(actionRow);
        }

        return { embeds: [embed], components };
    },
};