import asyncio
import logging
import os
from datetime import datetime
from pathlib import Path

from bleak import BleakClient, BleakGATTCharacteristic
from dotenv import load_dotenv
from rich.logging import RichHandler

from cryptography.hazmat.primitives.asymmetric.ec import \
    generate_private_key, SECP256R1, ECDH, EllipticCurvePublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

import characteristics as char
import constants as const

FILE_DIR = Path(__file__).parent
DOTENV_PATH = FILE_DIR / '.env'

load_dotenv(dotenv_path=DOTENV_PATH)

_logger = logging.getLogger()

logging.basicConfig(
    level="NOTSET", format="%(message)s", datefmt="[%X]", handlers=[RichHandler()]
)
sub_level = logging.WARNING
logging.getLogger('urllib3.connectionpool').setLevel(sub_level)
logging.getLogger('pygatt').setLevel(sub_level)
logging.getLogger('bleak.backends').setLevel(sub_level)

_logger.info(f"Set up logging @ {datetime.now().astimezone().isoformat()}")

class ClickBLE:

    def __init__(self, mac_address):
        self.mac = mac_address
        self.logger = logging.getLogger('ClickBLE')
        self.logger.info(f'Using MAC of "{self.mac}"')

        # encryption stuff
        self.private_key = generate_private_key(SECP256R1())
        self.public_key = self.private_key.public_key()
        self.public_bytes = self.public_key.public_bytes(
            encoding=Encoding.X962, 
            format=PublicFormat.UncompressedPoint
        )
        self.shared_key_bytes = None  # HKDF shared key bytes
        
        """https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESCCM"""
        self.nonce_bytes = None

        """
        The IV (initialization Vector) also called nonce (number used once) which 
        is an 8 byte array whose 4 first bytes are the 4 last bytes of the HKDF symmetric key
        followed by the 4 bytes of the counter you have received in the message
        """
        self.iv_bytes = None
        
    async def print_services(self, client):
        """From the Bleak examples; will print out all the characteristics it finds"""
        for service in client.services:
            self.logger.info("[Service] %s", service)

            for char in service.characteristics:
                if "read" in char.properties:
                    try:
                        value = await client.read_gatt_char(char.uuid)
                        extra = f", Value: {value}"
                    except Exception as e:
                        extra = f", Error: {e}"
                else:
                    extra = ""

                if "write-without-response" in char.properties:
                    extra += f", Max write w/o rsp size: {char.max_write_without_response_size}"

                self.logger.info(
                    "  [Characteristic] %s (%s)%s",
                    char,
                    ",".join(char.properties),
                    extra,
                )

                for descriptor in char.descriptors:
                    try:
                        value = await client.read_gatt_descriptor(descriptor.handle)
                        self.logger.info("    [Descriptor] %s, Value: %r", descriptor, value)
                    except Exception as e:
                        self.logger.error("    [Descriptor] %s, Error: %s", descriptor, e)

    def notification_handler(self, characteristic: BleakGATTCharacteristic, data: bytearray):
        """Simple notification handler which prints the data received."""
        self.logger.info(f"Received: {char.UUID_NAMES[characteristic.uuid.upper()]}: {data}")

    def async_notification_handler(self, characteristic: BleakGATTCharacteristic, data: bytearray):
        """Simple notification handler which prints the data received."""
        self.logger.info(f"Received on async char: {char.UUID_NAMES[characteristic.uuid.upper()]}: {data}")
        counter = data[:const.COUNTER_LENGTH]
        payload = data[const.COUNTER_LENGTH:]
        self.logger.debug(f"counter: {counter}")
        self.logger.debug(f"payload: {payload}")
        data = self.decrypt(counter, payload)

    def decrypt(self, counter, payload):
        if self.shared_key_bytes is None:
            raise ValueError("encryption key is not set up")
        # java code:
        # val aeadParameters = AEADParameters(KeyParameter(encryptionKeyBytes), MAC_LENGTH * 8, nonceBytes)
        # val ccmBlockCipher = CCMBlockCipher(aesEngine)
        # ccmBlockCipher.init(encrypt, aeadParameters)
        # val processed = ByteArray(ccmBlockCipher.getOutputSize(data.size))
        # ccmBlockCipher.processBytes(data, 0, data.size, processed, 0)
        # ccmBlockCipher.doFinal(processed, 0)
        # return processed
    
    def battery_notification_handler(self, characteristic: BleakGATTCharacteristic, data: bytearray):
        """Simple notification handler which prints the data received."""
        self.logger.info(f"Received on battery notify: {char.UUID_NAMES[characteristic.uuid.upper()]}: {data}")

    def process_characteristic(self, characteristic: BleakGATTCharacteristic, data: bytearray):
        """Main callback that farms out to the other ones"""
        self.logger.debug(f'Received on {char.UUID_NAMES[characteristic.uuid.upper()]}: "{data}"')
        if bytes(data[:8]) == const.RIDE_ON + const.RESPONSE_START:
            self.process_device_public_key(data)
        elif data[0] == const.DISCONNECT_MESSAGE_TYPE:
            self.logger.debug("Disconnect message")
        else:
            self.process_data(data)

    def process_data(self, data: bytearray):
        """Generic callback to log data"""
        self.logger.debug(f'Data: {data.hex()}"')

    def process_device_public_key(self, data: bytearray):
        """GATT Callback to setup shared key for encryption"""
        # first 8 bytes are communication header, then remainder is click's public key:
        self.logger.info(f'Click public key is {data[8:]}')
        if data[:8] == b'RideOn\x01\x03':
            # have to append 4 to indicate uncompressed:
            click_pub_key_bytes = b'\x04' + bytes(data[8:])
            click_pub_key = EllipticCurvePublicKey.from_encoded_point(SECP256R1(), click_pub_key_bytes)
            shared_secret = self.private_key.exchange(ECDH(), click_pub_key)
            self.shared_key_bytes = HKDF(
                algorithm=hashes.SHA256(),
                length=const.HKDF_LENGTH,
                salt=click_pub_key_bytes + self.public_bytes,
                info=b'handshake data',
            ).derive(shared_secret)
            self.iv_bytes = self.shared_key_bytes[const.KEY_LENGTH:]
            self.shared_key_bytes = self.shared_key_bytes[:const.KEY_LENGTH]
            pass

    async def try_read_char(self, label, char, client):
        try:
            res = await client.read_gatt_char(char)
            self.logger.info(f"{label} {res}")
        except Exception as e:
            self.logger.error(f'{label} Could not read characteristic "{char}": {e}')

    async def write_handshake(self):
        async with BleakClient(self.mac) as client:
            # await self.print_services(client)

            self.logger.debug("Reading characteristics")
            
            # device characteristc not found on linux for some reason...
            await self.try_read_char("Device name:", char.DEVICE_NAME_CHARACTERISTIC_UUID, client)
            await self.try_read_char("Appearance:", char.APPEARANCE_CHARACTERISTIC_UUID, client)
            await self.try_read_char("Manufacturer name:", char.MANUFACTURER_NAME_STRING_CHARACTERISTIC_UUID, client)
            await self.try_read_char("Serial:", char.SERIAL_NUMBER_STRING_CHARACTERISTIC_UUID, client)
            await self.try_read_char("HW Revision:", char.HARDWARE_REVISION_STRING_CHARACTERISTIC_UUID, client)
            await self.try_read_char("Firmware Revision:", char.FIRMWARE_REVISION_STRING_CHARACTERISTIC_UUID, client)


            self.logger.debug('Subscribing to characteristics')
            await client.start_notify(char.SERVICE_CHANGED_CHARACTERISTIC_UUID, self.notification_handler)
            await client.start_notify(char.ZWIFT_ASYNC_CHARACTERISTIC_UUID, self.async_notification_handler)
            await client.start_notify(char.ZWIFT_SYNC_TX_CHARACTERISTIC_UUID, self.process_characteristic)
            await client.start_notify(char.ZWIFT_UNKNOWN_6_CHARACTERISTIC_UUID, self.notification_handler)
            await client.start_notify(char.BATTERY_LEVEL_CHARACTERISTIC_UUID, self.battery_notification_handler)
            

            self.logger.info(f"starting handshake")
            pub_key = const.RIDE_ON + const.REQUEST_START + self.public_bytes[1:]
            self.logger.debug(f'Sending: {pub_key}')
            await client.write_gatt_char(
                char.ZWIFT_SYNC_RX_CHARACTERISTIC_UUID, 
                pub_key, 
                response=True
            )
            # await client.stop_notify(self.UUID_NOTIFY)

click = ClickBLE(os.environ.get('CLICK_MAC_ADDRESS'))

try:
    asyncio.run(click.write_handshake())
except Exception as e:
    _logger.error(f"Error getting data from click")
    _logger.exception(e)