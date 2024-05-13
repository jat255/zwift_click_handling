import asyncio
import json
import logging
import os
from datetime import datetime
from pathlib import Path

from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic
from dotenv import load_dotenv
from rich.logging import RichHandler
import blackboxprotobuf as bbpb

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
    level="INFO", format="%(message)s", datefmt="[%X]", handlers=[RichHandler()]
)
sub_level = logging.WARNING
logging.getLogger('urllib3.connectionpool').setLevel(sub_level)
logging.getLogger('pygatt').setLevel(sub_level)
logging.getLogger('bleak.backends').setLevel(sub_level)

_logger.info(f"Set up logging @ \"{datetime.now().astimezone().isoformat()}\"")

class ClickBLE:

    def __init__(self, mac_address: str, encrypted: bool):
        self.logger = logging.getLogger('ClickBLE')
        self.logger.info(f"Setting up BLE client {'**WITH**' if encrypted else '**WITHOUT**'} encryption")
        self.logger.info(f'Using MAC of "{mac_address}"')
        self.mac = mac_address
        self.encrypted = encrypted
        self.button_up_pressed = False
        self.button_down_pressed = False
        self.last_button_up_pressed = False
        self.last_button_down_pressed = False
    
        # encryption stuff
        if self.encrypted:
            self.private_key = generate_private_key(SECP256R1())
            self.public_key = self.private_key.public_key()
            self.public_bytes = self.public_key.public_bytes(
                encoding=Encoding.X962, 
                format=PublicFormat.UncompressedPoint
            )
            self.shared_key_bytes = bytearray()  # HKDF shared key bytes
            
            """https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESCCM"""
            """
            The IV (initialization Vector) also called nonce (number used once) which 
            is an 8 byte array whose 4 first bytes are the 4 last bytes of the HKDF symmetric key
            followed by the 4 bytes of the counter you have received in the message
            """
            self.iv_bytes = bytearray()
        else:
            self.private_key = None
            self.public_key = None
            self.public_bytes = b''
            self.shared_key_bytes = b''
            self.iv_bytes = bytearray()
        
    def notification_handler(self, characteristic: BleakGATTCharacteristic, data: bytearray):
        """Simple notification handler which prints the data received."""
        self.logger.info(f"Received: {char.UUID_NAMES[characteristic.uuid.upper()]}: {data}")

    def async_notification_handler(self, characteristic: BleakGATTCharacteristic, data: bytearray):
        """Simple notification handler which prints the data received."""
        self.logger.debug(f"Received on async char: {char.UUID_NAMES[characteristic.uuid.upper()]}: {data}")
        if self.encrypted:
            counter_bytes = data[:const.COUNTER_LENGTH]
            payload_bytes = data[const.COUNTER_LENGTH: -1 * const.MAC_LENGTH]
            tag_bytes = data[-1 * const.MAC_LENGTH:]
            self.logger.debug(f"counter_bytes: {counter_bytes}")
            self.logger.debug(f"payload_bytes: {payload_bytes}")
            self.logger.debug(f"tag_bytes: {tag_bytes}")
            response = self.decrypt(counter_bytes, payload_bytes, tag_bytes) 
        else:
            response = data
            type = bytes(data[:1])
            payload = bytes(data[1:])
            pb_tuple = bbpb.protobuf_to_json(payload)
            data_dict = json.loads(pb_tuple[0])
            self.logger.debug(f'Message type is "{const.types[type]}"')
            self.logger.debug(f'Message data is {data_dict}')
            if type == const.BATTERY_LEVEL_TYPE:
                pass
            elif type == const.CLICK_NOTIFICATION_MESSAGE_TYPE:
                """
                appears that the message will have two keys for each button
                "Plus" button corresponds to key '1'
                "Minus" button corresponds to key '2'
                value will be 0 if button is pressed and 1 if value is released
                
                A single button press of the "minus" button will return data such as:
                {'1': 1, '2': 0}  // this is the press of the button
                {'1': 1, '2': 1}  // this is the release of the button
                {'1': 1, '2': 1}
                {'1': 1, '2': 1}
                
                A single button press of the "plus" button will return data such as:
                {'1': 0, '2': 1}   // this is the press of the button
                {'1': 0, '2': 1}
                {'1': 1, '2': 1}   // this is the release of the button
                {'1': 1, '2': 1}
                """
                # there's a better way to handle this, but I'm lazy...
                self.last_button_up_pressed = self.button_up_pressed
                self.last_button_down_pressed = self.button_down_pressed
                self.button_down_pressed = data_dict['2'] == 0
                self.button_up_pressed = data_dict['1'] == 0
                if self.button_up_pressed != self.last_button_up_pressed:
                    self.logger.info(f"Plus button {'PRESSED' if self.button_up_pressed else 'RELEASED'}")
                if self.button_down_pressed != self.last_button_down_pressed:
                    self.logger.info(f"Minus button {'PRESSED' if self.button_down_pressed else 'RELEASED'}")
        
    def decrypt(self, counter_bytes: bytearray, payload_bytes: bytearray, tag_bytes: bytearray):
        if not self.encrypted:
            raise ValueError("client not configured for encryption")
        if self.shared_key_bytes is None:
            raise ValueError("encryption key is not set up")
        
        # this is not working... not sure if the issue is in the key generation or the
        # actual deccryption part, but it turns out we don't really need the encryption for our
        # purposes anyway
        raise NotImplementedError("This implementation isn't working yet (or maybe ever...)")
        nonce_bytes = self.iv_bytes + counter_bytes
        aesccm = AESCCM(self.shared_key_bytes, tag_length=4)
        data = aesccm.decrypt(nonce_bytes, payload_bytes, tag_bytes)
        
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
        self.logger.debug(f"Received on battery notify: {char.UUID_NAMES[characteristic.uuid.upper()]}: {data}")

    def process_characteristic(self, characteristic: BleakGATTCharacteristic, data: bytearray):
        """Main callback that farms out to the other ones"""
        self.logger.debug(f'Received on {char.UUID_NAMES[characteristic.uuid.upper()]}: "{data}"')
        
        # encryption key response:
        if bytes(data[:8]) == const.RIDE_ON + const.RESPONSE_START:
            self.process_device_public_key(data)
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
            if self.private_key:
                shared_secret = self.private_key.exchange(ECDH(), click_pub_key)
                self.shared_key_bytes = HKDF(
                    algorithm=hashes.SHA256(),
                    length=const.HKDF_LENGTH,
                    salt=click_pub_key_bytes + self.public_bytes,
                    info=b'handshake data',
                ).derive(shared_secret)
                self.iv_bytes = self.shared_key_bytes[const.KEY_LENGTH:]
                self.shared_key_bytes = self.shared_key_bytes[:const.KEY_LENGTH]

    async def try_read_char(self, label, char, client):
        try:
            res = await client.read_gatt_char(char)
            self.logger.info(f"{label} {res}")
        except Exception as e:
            self.logger.error(f'{label} Could not read characteristic "{char}": {e}')

    async def read_chars(self):
        async with BleakClient(self.mac) as client:
            self.logger.debug("Reading characteristics")
                
            # device characteristc not found on linux for some reason...
            await self.try_read_char("Device name:", char.DEVICE_NAME_CHARACTERISTIC_UUID, client)
            await self.try_read_char("Appearance:", char.APPEARANCE_CHARACTERISTIC_UUID, client)
            await self.try_read_char("Manufacturer name:", char.MANUFACTURER_NAME_STRING_CHARACTERISTIC_UUID, client)
            await self.try_read_char("Serial:", char.SERIAL_NUMBER_STRING_CHARACTERISTIC_UUID, client)
            await self.try_read_char("HW Revision:", char.HARDWARE_REVISION_STRING_CHARACTERISTIC_UUID, client)
            await self.try_read_char("Firmware Revision:", char.FIRMWARE_REVISION_STRING_CHARACTERISTIC_UUID, client)

    async def write_handshake(self):
        async with BleakClient(self.mac) as client:
            self.logger.debug('Subscribing to characteristics')
            await client.start_notify(char.SERVICE_CHANGED_CHARACTERISTIC_UUID, self.notification_handler)
            await client.start_notify(char.ZWIFT_ASYNC_CHARACTERISTIC_UUID, self.async_notification_handler)
            await client.start_notify(char.ZWIFT_SYNC_TX_CHARACTERISTIC_UUID, self.process_characteristic)
            await client.start_notify(char.ZWIFT_UNKNOWN_6_CHARACTERISTIC_UUID, self.notification_handler)
            await client.start_notify(char.BATTERY_LEVEL_CHARACTERISTIC_UUID, self.battery_notification_handler)
            

            self.logger.info(f"Starting handshake")
            if self.encrypted:
                pub_key = const.RIDE_ON + const.REQUEST_START + self.public_bytes[1:]
            else:
                pub_key = const.RIDE_ON
            self.logger.debug(f'Sending: {pub_key}')
            await client.write_gatt_char(
                char.ZWIFT_SYNC_RX_CHARACTERISTIC_UUID, 
                pub_key, 
                response=True
            )
            self.logger.info(f"Finished handshake; waiting for input")
            await asyncio.sleep(100)

MAC = os.environ.get('CLICK_MAC_ADDRESS')
if not MAC:
    raise EnvironmentError('"CLICK_MAC_ADDRESS" must be defined')
ENCRYPTION = os.environ.get('ADT_email_send', str(False)).lower() == 'true'

click = ClickBLE(MAC, encrypted=ENCRYPTION)

try:
    # asyncio.run(click.read_chars())
    asyncio.run(click.write_handshake())
except Exception as e:
    _logger.error(f"Error getting data from click")
    _logger.exception(e)