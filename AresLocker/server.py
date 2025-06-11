import discord
import asyncio
import os
import re

TOKEN = "DEIN_DISCORD_BOT_TOKEN"  # Deinen Bot Token hier eintragen
CHANNEL_ID = 123456789012345678   # Channel-ID hier eintragen
OUTPUT_FILE = "key_reconstructed.txt"

client = discord.Client(intents=discord.Intents.default())

# Regex, um "Chunk X/Y" aus der Nachricht zu parsen
chunk_pattern = re.compile(r"Chunk (\d+)/(\d+)\n([0-9a-fA-F]+)")

async def download_and_reassemble():
    channel = client.get_channel(CHANNEL_ID)
    if channel is None:
        print(f"Channel mit ID {CHANNEL_ID} nicht gefunden.")
        await client.close()
        return

    print("Lese Nachrichten aus dem Channel...")

    chunks = {}
    total_chunks = None

    # Nachrichten chronologisch abrufen (discord.py liefert sie in umgekehrter Reihenfolge)
    messages = await channel.history(limit=200).flatten()
    messages.reverse()

    for msg in messages:
        match = chunk_pattern.match(msg.content)
        if match:
            idx = int(match.group(1))
            total = int(match.group(2))
            data_hex = match.group(3)

            if total_chunks is None:
                total_chunks = total
            elif total_chunks != total:
                print(f"Warnung: Unterschiedliche Gesamtchunkzahl in Nachrichten gefunden.")

            chunks[idx] = bytes.fromhex(data_hex)
            print(f"Chunk {idx} von {total_chunks} geladen.")

    if total_chunks is None:
        print("Keine Chunks gefunden.")
        await client.close()
        return

    if len(chunks) != total_chunks:
        print(f"Warnung: Nicht alle Chunks gefunden ({len(chunks)}/{total_chunks})")

    print("Schreibe rekonstruierte Datei...")

    with open(OUTPUT_FILE, 'wb') as out_file:
        for i in range(1, total_chunks + 1):
            if i not in chunks:
                print(f"Fehlender Chunk {i}, Datei möglicherweise unvollständig.")
                continue
            out_file.write(chunks[i])

    print(f"Datei erfolgreich als {OUTPUT_FILE} geschrieben.")
    await client.close()

@client.event
async def on_ready():
    print(f"Bot eingeloggt als {client.user}")
    await download_and_reassemble()

if __name__ == "__main__":
    client.run(TOKEN)