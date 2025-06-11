import discord
import asyncio
import os
import logging
from config import Config

TOKEN = Config.TOKEN
CHANNEL_ID = Config.CHANNEL_ID
FILEPATH = Config.FILEPATH
CHUNK_SIZE = Config.CHUNK_SIZE

# Logging Setup
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')

intents = discord.Intents.default()
intents.guilds = True
intents.messages = True
client = discord.Client(intents=intents)

async def send_file_chunks():
    try:
        channel = await client.fetch_channel(CHANNEL_ID)
    except Exception as e:
        logging.error(f"Channel mit ID {CHANNEL_ID} konnte nicht abgerufen werden: {e}")
        await client.close()
        return

    try:
        file_size = os.path.getsize(FILEPATH)
        total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE

        with open(FILEPATH, 'rb') as f:
            chunk_index = 0
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                chunk_index += 1
                message = f"Chunk {chunk_index}/{total_chunks}\n{chunk.hex()}"
                try:
                    await channel.send(message)
                    logging.info(f"Gesendet: Chunk {chunk_index} von {total_chunks}")
                except Exception as send_err:
                    logging.error(f"Fehler beim Senden von Chunk {chunk_index}: {send_err}")
                    await asyncio.sleep(2)
                await asyncio.sleep(0.5)  # Rate Limit

        logging.info("Alle Chunks gesendet, lösche lokale Datei...")
        try:
            os.remove(FILEPATH)
            logging.info("Datei gelöscht.")
        except Exception as del_err:
            logging.error(f"Fehler beim Löschen der Datei: {del_err}")

    except Exception as e:
        logging.error(f"Fehler: {e}")

    await client.close()

@client.event
async def on_ready():
    logging.info(f"Bot eingeloggt als {client.user}")
    await send_file_chunks()

def main():
    try:
        client.run(TOKEN)
    except KeyboardInterrupt:
        logging.info("Bot wurde manuell beendet.")

if __name__ == "__main__":
    main()
