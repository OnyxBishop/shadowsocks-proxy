import os

class Config:
    BOT_TOKEN = os.getenv('BOT_TOKEN', '')
    PROXY_HOST = os.getenv('PROXY_HOST', '0.0.0.0')
    PROXY_PORT = int(os.getenv('PROXY_PORT', '1080'))
    SS_Master_Secret = os.getenv('SS_MASTER_SECRET', '')
    SS_Method = os.getenv('SS_METHOD', 'chacha20-ietf-poly1305')
    OUTLINE_API_URL=os.getenv('OUTLINE_API_URL', '')

    @classmethod
    def admin_ids(cls) -> list[int]:
        admin_ids_str = os.getenv('ADMIN_IDS', '')
        return [int(x) for x in admin_ids_str.split(',') if x.strip().isdigit()]
