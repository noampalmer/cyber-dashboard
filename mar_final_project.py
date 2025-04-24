COMPLETE SECURITY MONITORING SYSTEM - SINGLE FILE SOLUTION (Versatile SIEM/SOAR + Sensors)
Features:
- Auto-installs all dependencies
- MFA/2FA (TOTP) Support for Application Startup
- RTSP/ONVIF Camera Support (including PTZ)
- *** Fence Sensor Integration (Log File Input) ***
- Configurable SIEM Integration (Splunk, Elastic)
- Configurable SOAR Integration (SplunkSOAR, CortexXSOAR)
- Motion Detection with OpenCV
- Modern PyQt6 GUI with Dark Mode
- Dynamic Camera/Sensor Configuration (Add/Remove)
- Visual Map View for Camera & Sensor Placement
- Sensor Alert Visualization and Camera Association
- Robust error handling and user feedback

SECURITY CONSIDERATIONS:
-----------------------
(Same as before - protect config.yaml, use ENV vars, secure MFA, network, etc.)
- SENSOR LOG FILE (e.g., sensor_alerts.log): Ensure appropriate permissions. If sensitive data might appear, protect it.

NEW CONFIG SECTIONS:
-------------------
- fence_sensors: Defines individual sensors (ID, name, type, location, severity, associated cameras).
- sensor_input: Configures how sensor data is received (currently 'logfile').
- map_view.item_positions: Replaces 'camera_positions', stores locations for both cameras and sensors.
"""

import os
import sys
import subprocess
import platform
import time
import datetime
import json
from typing import List, Dict, Optional, Tuple, Any, Union
from enum import Enum
import logging
import asyncio
import re
from html import escape
import abc # Added for Abstract Base Classes
import traceback # For detailed error logging
import io # For QR code in memory
import copy # Used for config dialog and deep copies

# ==================== LOGGING SETUP ====================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(threadName)s] %(message)s')
logger = logging.getLogger(__name__)

# ==================== ENVIRONMENT VARIABLE HELPERS ====================
def get_env_variable(var_name: str, default: Optional[str] = None) -> Optional[str]:
    """Gets an environment variable, returning None if not found (unless default is specified)."""
    return os.environ.get(var_name, default)

def resolve_config_value(value: Any) -> Any:
    """If value is a string like 'ENV:VAR_NAME', resolve it from environment variables."""
    if isinstance(value, str) and value.startswith("ENV:"):
        var_name = value[4:]
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', var_name):
             logger.error(f"Invalid environment variable name format specified in config: '{var_name}'. Must match ^[a-zA-Z_][a-zA-Z0-9_]*$")
             return None
        env_val = get_env_variable(var_name)
        if env_val is None:
            logger.warning(f"Config specified environment variable '{var_name}' but it was not found in the environment.")
            return None
        logger.debug(f"Resolved env var '{var_name}' successfully.")
        return env_val
    return value

# ==================== AUTO-INSTALLER ====================
def install_packages():
    """Checks and installs required Python packages using pip."""
    logger.warning("Attempting dependency auto-installation. For secure environments, manage dependencies manually using requirements.txt and a virtual environment.")
    required = {
        'opencv-python': 'cv2',
        'numpy': 'numpy',
        'PyQt6': 'PyQt6',
        'requests': 'requests',
        'pyyaml': 'yaml',
        'Pillow': 'PIL',
        'onvif-zeep': 'onvif',
        'zeep': 'zeep',
        # --- MFA Dependencies ---
        'pyotp': 'pyotp',
        'keyring': 'keyring',
        'qrcode': 'qrcode',
    }
    installed_something = False
    for pkg, import_name in required.items():
        if not re.match(r'^[a-zA-Z0-9._-]+(?:==[a-zA-Z0-9.]+)?$', pkg):
             logger.error(f"❌ Invalid package name format detected: '{pkg}'. Skipping installation.")
             continue
        try:
            if '.' in import_name: __import__(import_name.split('.')[0])
            else: __import__(import_name)
        except ImportError:
            logger.info(f"⚙️ Package '{pkg}' not found. Installing...")
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "--upgrade", pkg, "--disable-pip-version-check", "--no-cache-dir"],
                    capture_output=True, text=True, check=True, timeout=120
                )
                if result.stderr: logger.warning(f"Pip install stderr for {pkg}: {result.stderr[:500]}...")
                logger.info(f"✅ Successfully installed {pkg}.")
                installed_something = True
            except subprocess.TimeoutExpired:
                 logger.error(f"❌ Failed to install {pkg}. Installation timed out.")
                 print(f"❌ Error installing {pkg} (Timeout). Please try installing it manually and restart.")
                 sys.exit(1)
            except subprocess.CalledProcessError as e:
                error_output = e.stderr if e.stderr else e.stdout
                logger.error(f"❌ Failed to install {pkg}. Pip Error: {error_output[:500]}...")
                print(f"❌ Error installing {pkg}. Please try manually: '{sys.executable} -m pip install {pkg}'")
                sys.exit(1)
            except Exception as e:
                logger.error(f"❌ Unexpected error during installation of {pkg}. Error: {e}", exc_info=True)
                sys.exit(1)

install_packages()

# ==================== CORE IMPORTS ====================
try:
    import cv2
    import numpy as np
    import requests
    import yaml
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
        QLabel, QPushButton, QTextEdit, QComboBox, QSlider, QTabWidget, QToolBar,
        QGroupBox, QStatusBar, QFileDialog, QMessageBox, QLineEdit, QFormLayout,
        QListWidget, QListWidgetItem, QInputDialog, QDialog, QDialogButtonBox,
        QSizePolicy, QGraphicsView, QGraphicsScene, QGraphicsPixmapItem, QGraphicsItem,
        QGraphicsDropShadowEffect, QCheckBox, QScrollArea, QPlainTextEdit, QSpinBox,
        QDoubleSpinBox # Added for location input
    )
    from PyQt6.QtGui import (
        QImage, QPixmap, QIcon, QPalette, QColor, QAction, QFont, QActionGroup,
        QPainter, QTextCursor, QPen, QBrush, QTransform, QDesktopServices
    )
    from PyQt6.QtCore import (
        Qt, QTimer, QThread, pyqtSignal, QPoint, QSize, QRectF, QPointF,
        QPropertyAnimation, QEasingCurve, QVariantAnimation, QRect, pyqtSlot, QMetaObject, Q_ARG,
        QUrl
    )
    try:
        from onvif import ONVIFCamera
        from zeep.exceptions import Fault, TransportError, XMLSyntaxError
    except ImportError:
        ONVIFCamera = None
        Fault = TransportError = XMLSyntaxError = Exception
        logger.warning("onvif-zeep library not found or failed to import. ONVIF functionality will be disabled.")

    from requests.exceptions import ConnectionError as RequestsConnectionError, Timeout, RequestException
    from PIL import Image

    # --- MFA Imports ---
    import pyotp
    import keyring
    import keyring.errors
    import qrcode
    # --- End MFA Imports ---

except ImportError as e:
    logger.critical(f"❌ Critical import failed after installation attempt: {e}. Please ensure all dependencies were installed correctly.", exc_info=True)
    if QApplication.instance(): QMessageBox.critical(None, "Import Error", f"Failed to import a required library: {e}\n\nPlease check installation and restart.")
    else: print(f"❌ Failed to import a required library: {e}. Exiting.", file=sys.stderr)
    sys.exit(1)


# ==================== MFA/2FA CONSTANTS and HELPERS ====================
KEYRING_SERVICE_NAME = "SecurityMonitorPro-TOTP" # Unique name for keyring service
KEYRING_USERNAME = "user_secret" # Key name for the TOTP secret
KEYRING_RECOVERY_CODES_KEY = "user_recovery_codes" # Key name for recovery codes (stored joined by space)
NUM_RECOVERY_CODES = 10

class KeyringError(Exception):
    """Custom exception for keyring errors."""
    pass

def get_totp_secret() -> Optional[str]:
    """Retrieve the TOTP secret from the keyring."""
    try:
        secret = keyring.get_password(KEYRING_SERVICE_NAME, KEYRING_USERNAME)
        logger.debug(f"Keyring: Attempted to retrieve secret for service='{KEYRING_SERVICE_NAME}', username='{KEYRING_USERNAME}'. Found: {'Yes' if secret else 'No'}")
        return secret
    except keyring.errors.NoKeyringError:
        logger.error("Keyring backend not found. Please ensure a suitable backend (like gnome-keyring, KWallet, macOS Keychain, Windows Credential Manager) is installed and configured.")
        raise KeyringError("No keyring backend available. Cannot manage MFA secrets.")
    except Exception as e:
        logger.error(f"Unexpected error retrieving secret from keyring: {e}", exc_info=True)
        raise KeyringError(f"Failed to retrieve secret from keyring: {type(e).__name__}")

def set_totp_secret(secret: str):
    """Store the TOTP secret in the keyring."""
    try:
        keyring.set_password(KEYRING_SERVICE_NAME, KEYRING_USERNAME, secret)
        logger.info(f"Keyring: Stored secret successfully for service='{KEYRING_SERVICE_NAME}', username='{KEYRING_USERNAME}'.")
    except keyring.errors.NoKeyringError:
        logger.error("Keyring backend not found. Please ensure a suitable backend is installed and configured.")
        raise KeyringError("No keyring backend available. Cannot store MFA secret.")
    except Exception as e:
        logger.error(f"Unexpected error setting secret in keyring: {e}", exc_info=True)
        raise KeyringError(f"Failed to store secret in keyring: {type(e).__name__}")

def delete_totp_secret():
    """Delete the TOTP secret from the keyring."""
    try:
        keyring.delete_password(KEYRING_SERVICE_NAME, KEYRING_USERNAME)
        logger.info(f"Keyring: Deleted secret successfully for service='{KEYRING_SERVICE_NAME}', username='{KEYRING_USERNAME}'.")
    except keyring.errors.PasswordDeleteError:
        logger.warning(f"Keyring: Secret for service='{KEYRING_SERVICE_NAME}', username='{KEYRING_USERNAME}' not found or could not be deleted.")
        pass # Okay if it doesn't exist
    except keyring.errors.NoKeyringError:
        logger.error("Keyring backend not found.")
        raise KeyringError("No keyring backend available. Cannot delete MFA secret.")
    except Exception as e:
        logger.error(f"Unexpected error deleting secret from keyring: {e}", exc_info=True)
        raise KeyringError(f"Failed to delete secret from keyring: {type(e).__name__}")

def store_recovery_codes(codes: List[str]):
    """Store recovery codes (space-separated) in the keyring."""
    if not codes: return
    codes_str = " ".join(codes)
    try:
        keyring.set_password(KEYRING_SERVICE_NAME, KEYRING_RECOVERY_CODES_KEY, codes_str)
        logger.info("Keyring: Stored recovery codes.")
    except Exception as e:
        logger.error(f"Failed to store recovery codes in keyring: {e}", exc_info=True)
        raise KeyringError(f"Failed to store recovery codes securely: {type(e).__name__}")

def get_recovery_codes() -> Optional[List[str]]:
    """Retrieve recovery codes from the keyring."""
    try:
        codes_str = keyring.get_password(KEYRING_SERVICE_NAME, KEYRING_RECOVERY_CODES_KEY)
        if codes_str:
            logger.debug("Keyring: Retrieved recovery codes string.")
            return codes_str.split()
        logger.debug("Keyring: No recovery codes found.")
        return None
    except Exception as e:
        logger.error(f"Failed to retrieve recovery codes from keyring: {e}", exc_info=True)
        raise KeyringError(f"Failed to retrieve recovery codes: {type(e).__name__}")

def delete_recovery_codes():
    """Delete recovery codes from the keyring."""
    try:
        keyring.delete_password(KEYRING_SERVICE_NAME, KEYRING_RECOVERY_CODES_KEY)
        logger.info("Keyring: Deleted recovery codes.")
    except keyring.errors.PasswordDeleteError:
        pass # Ignore if not found
    except Exception as e:
        logger.error(f"Failed to delete recovery codes from keyring: {e}", exc_info=True)

def verify_totp_code(secret: str, code: str) -> bool:
    """Verify a TOTP code against the secret."""
    if not secret or not code: return False
    code = code.replace(" ", "") # Remove spaces
    if not code.isdigit() or len(code) != 6: return False
    try:
        totp = pyotp.TOTP(secret)
        # Allow 1 interval drift (30s before or after)
        is_valid = totp.verify(code, valid_window=1)
        logger.debug(f"TOTP Verification Result: {'Valid' if is_valid else 'Invalid'}")
        return is_valid
    except Exception as e:
        logger.error(f"Error during TOTP verification: {e}", exc_info=True)
        return False

def use_recovery_code(code_to_use: str) -> bool:
    """Checks if the code is a valid recovery code and removes it if found."""
    if not code_to_use: return False
    code_to_use = code_to_use.strip()
    try:
        codes = get_recovery_codes()
        if codes and code_to_use in codes:
            codes.remove(code_to_use)
            store_recovery_codes(codes) # Store the updated list
            logger.info(f"Successfully used recovery code. {len(codes)} remaining.")
            return True
        logger.warning(f"Recovery code '{code_to_use}' not found or invalid.")
        return False
    except KeyringError as e:
        logger.error(f"Keyring error using recovery code: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error validating recovery code: {e}", exc_info=True)
        return False


# ==================== INTERFACE DEFINITIONS ====================
class SIEMInterface(abc.ABC):
    """Abstract Base Class for SIEM client implementations."""
    def __init__(self, config: dict):
        self.config = config
        self.is_configured: bool = False
        self.api_url: Optional[str] = None
        self.auth_token: Optional[str] = None # Generic token/API key
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.verify_ssl: bool = True
        self.session = requests.Session() # Common session
        self._resolve_common_config() # Call resolver in base __init__

    @abc.abstractmethod
    def _resolve_common_config(self):
        """Resolves common configuration parameters. MUST be implemented by subclasses
           to set self.is_configured correctly based on the specific SIEM's needs."""
        # Basic resolution, subclasses MUST refine self.is_configured
        self.api_url = resolve_config_value(self.config.get('api_url'))
        self.auth_token = resolve_config_value(self.config.get('auth_token') or self.config.get('token') or self.config.get('api_key'))
        self.username = resolve_config_value(self.config.get('username'))
        self.password = resolve_config_value(self.config.get('password'))
        self.verify_ssl = self.config.get('verify_ssl', True)
        logger.info(f"{self.__class__.__name__} attempting config resolution.")
        if not self.verify_ssl:
            logger.critical(f"{self.__class__.__name__} SECURITY WARNING: SSL verification DISABLED!")
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except ImportError: pass

    @abc.abstractmethod
    def fetch_alerts(self) -> List[Dict]:
        """Fetches alerts from the SIEM system. Must be implemented by subclasses."""
        pass

    def check_connection(self) -> bool:
        """Optional: Method to test connectivity to the SIEM API."""
        logger.warning(f"'check_connection' not implemented for {self.__class__.__name__}")
        return False

class SOARInterface(abc.ABC):
    """Abstract Base Class for SOAR client implementations."""
    def __init__(self, config: dict):
        self.config = config
        self.is_configured: bool = False
        self.api_url: Optional[str] = None
        self.auth_token: Optional[str] = None # Generic token/API key
        self.verify_ssl: bool = True
        self.session = requests.Session() # Common session
        self._resolve_common_config()

    @abc.abstractmethod
    def _resolve_common_config(self):
        """Resolves common configuration parameters. MUST be implemented by subclasses
           to set self.is_configured correctly."""
        self.api_url = resolve_config_value(self.config.get('api_url'))
        self.auth_token = resolve_config_value(self.config.get('auth_token') or self.config.get('token') or self.config.get('api_key'))
        self.verify_ssl = self.config.get('verify_ssl', True)
        logger.info(f"{self.__class__.__name__} attempting config resolution.")
        if not self.verify_ssl:
            logger.critical(f"{self.__class__.__name__} SECURITY WARNING: SSL verification DISABLED!")
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except ImportError: pass

    @abc.abstractmethod
    def trigger_action(self, action_name: str, parameters: Dict) -> Dict:
        """Triggers a generic action on the SOAR system."""
        pass

    def check_connection(self) -> bool:
        """Optional: Method to test connectivity to the SOAR API."""
        logger.warning(f"'check_connection' not implemented for {self.__class__.__name__}")
        return False


# ==================== SYSTEM COMPONENTS ====================
def sanitize_filename(filename: str) -> str:
    """Removes potentially dangerous characters for use in filenames or internal keys."""
    if not isinstance(filename, str): return "invalid_name"
    filename = filename.replace('/', '_').replace('\\', '_').replace('..', '_')
    filename = re.sub(r'[^\w.\-]+', '_', filename) # Allow word chars, dot, hyphen
    filename = filename.strip('._- ')
    filename = re.sub(r'[-._]{2,}', '_', filename)
    max_len = 100
    if len(filename) > max_len: filename = filename[:max_len].strip('._- ')
    if not filename or filename == '.': filename = f"sanitized_{int(time.time())}"
    return filename

class SecurityCamera:
    """Handles connection, frame retrieval, motion detection, and PTZ for a single camera."""
    def __init__(self, config: dict):
        self.config = config
        raw_name = config.get('name', f'UnnamedCamera_{int(time.time())}')
        self.name = sanitize_filename(raw_name)
        self.raw_name = raw_name
        if self.name != self.raw_name:
            logger.warning(f"Camera name '{self.raw_name}' sanitized to '{self.name}' for internal use.")

        self.url = resolve_config_value(config.get('url'))
        self.host = resolve_config_value(config.get('host'))
        self.port = resolve_config_value(config.get('port'))
        self.user = resolve_config_value(config.get('user'))
        self.password = resolve_config_value(config.get('password'))

        if self.url and '://' in self.url and '@' in self.url.split('://')[1]:
            logger.warning(f"Camera '{self.name}': Credentials seem embedded in the RTSP URL.")

        self.is_onvif = config.get('onvif', False)
        self.motion_threshold = config.get('motion_threshold', 500)

        self.cap: Optional[cv2.VideoCapture] = None
        self.onvif_cam: Optional[ONVIFCamera] = None
        self.ptz = None
        self.media_profile = None
        self.ptz_configuration_token: Optional[str] = None
        self.prev_frame_gray: Optional[np.ndarray] = None
        self.is_connected: bool = False
        self.is_connecting: bool = False
        self.last_connection_attempt_time: float = 0
        self.connection_retry_delay: int = 15
        self.last_error: Optional[str] = None
        logger.debug(f"Initializing camera object: {self.name} (Raw: {self.raw_name}, ONVIF: {self.is_onvif}) URL/Host provided: {bool(self.url or self.host)}")

    def _set_error(self, message: str, log_level=logging.ERROR):
        log_func = logger.error if log_level == logging.ERROR else (logger.warning if log_level == logging.WARNING else logger.info)
        log_func(f"Camera ({self.name}): {message}")
        self.last_error = message
        if log_level >= logging.ERROR:
            if self.is_connected: logger.info(f"Camera '{self.name}' state changed to DISCONNECTED due to error.")
            self.is_connected = False
            self.release_capture()
            self.onvif_cam = None; self.ptz = None; self.media_profile = None

    def release_capture(self):
        if self.cap is not None:
            logger.debug(f"Releasing video capture for {self.name}")
            try: self.cap.release()
            except Exception as e: logger.error(f"Exception releasing capture for {self.name}: {e}")
            self.cap = None

    def connect(self) -> bool:
        if self.is_connecting or self.is_connected: return self.is_connected
        current_time = time.time()
        if current_time - self.last_connection_attempt_time < self.connection_retry_delay: return False

        self.is_connecting = True
        self.last_connection_attempt_time = current_time
        logger.info(f"Attempting connection to camera: {self.name} (Raw: {self.raw_name})")
        self.last_error = None
        self.release_capture(); self.onvif_cam = None; self.ptz = None

        stream_uri = self.url

        try:
            if self.is_onvif:
                if not ONVIFCamera:
                    self._set_error("ONVIF connection failed: 'onvif-zeep' library not available."); self.is_connecting = False; return False
                if not self.host or not self.port or self.user is None or self.password is None:
                     self._set_error("ONVIF connection failed: Host, Port, User, or Password missing/unresolved."); self.is_connecting = False; return False

                logger.info(f"Connecting to {self.name} via ONVIF: {self.host}:{self.port} (User: {self.user})")
                try:
                    import onvif
                    wsdl_dir = os.path.join(os.path.dirname(onvif.__file__), 'wsdl')
                    if not os.path.exists(wsdl_dir):
                         wsdl_dir_alt = os.path.join(os.path.dirname(os.path.dirname(onvif.__file__)), 'onvif_wsdl')
                         if os.path.exists(wsdl_dir_alt): wsdl_dir = wsdl_dir_alt
                         else:
                             wsdl_dir_script = os.path.join(os.path.dirname(__file__), 'wsdl')
                             if os.path.exists(wsdl_dir_script): wsdl_dir = wsdl_dir_script
                             else:
                                 site_packages_path = os.path.dirname(os.path.dirname(requests.__file__))
                                 wsdl_site_path = os.path.join(site_packages_path, 'onvif', 'wsdl')
                                 if os.path.exists(wsdl_site_path): wsdl_dir = wsdl_site_path
                                 else: raise FileNotFoundError("ONVIF WSDL directory not found in expected locations.")
                    logger.debug(f"Using ONVIF WSDL directory: {wsdl_dir}")
                except Exception as e:
                    self._set_error(f"ONVIF WSDL files lookup failed: {e}."); self.is_connecting = False; return False

                try:
                    self.onvif_cam = ONVIFCamera(self.host, self.port, self.user, self.password, wsdl_dir=wsdl_dir, transport_timeout=10)
                    device_info = self.onvif_cam.devicemgmt.GetDeviceInformation()
                    logger.info(f"ONVIF device connected: {device_info.Manufacturer} {device_info.Model}")
                    media_service = self.onvif_cam.create_media_service()
                    profiles = media_service.GetProfiles()
                    if not profiles: self._set_error("No media profiles found via ONVIF."); self.is_connecting = False; return False
                    video_profiles = [p for p in profiles if hasattr(p, 'VideoEncoderConfiguration') and p.VideoEncoderConfiguration]
                    self.media_profile = video_profiles[0] if video_profiles else profiles[0]
                    logger.info(f"Using ONVIF media profile: {self.media_profile.Name} (Token: {self.media_profile.token})")

                    req = media_service.create_type('GetStreamUri')
                    req.ProfileToken = self.media_profile.token
                    obtained_uri = None
                    try:
                         req.StreamSetup = {'Stream': 'RTP-Unicast', 'Transport': {'Protocol': 'TCP'}}
                         obtained_uri = media_service.GetStreamUri(req).Uri
                         logger.info(f"Got ONVIF stream URI (TCP) for {self.name}")
                    except Exception:
                         logger.warning(f"Failed TCP stream URI for {self.name}, trying UDP.")
                         try:
                             req.StreamSetup = {'Stream': 'RTP-Unicast', 'Transport': {'Protocol': 'UDP'}}
                             obtained_uri = media_service.GetStreamUri(req).Uri
                             logger.info(f"Got ONVIF stream URI (UDP) for {self.name}")
                         except Exception:
                              logger.warning(f"Failed UDP stream URI for {self.name}, trying profile attributes.")
                              for attr_name in ['Uri', 'MediaUri', 'RTSPStreamUri', 'StreamUri']:
                                  if hasattr(self.media_profile, attr_name):
                                     uri_val = getattr(self.media_profile, attr_name)
                                     if isinstance(uri_val, str) and uri_val.startswith("rtsp://"):
                                         obtained_uri = uri_val; logger.info(f"Using RTSP URI from profile attribute '{attr_name}'"); break
                                     elif isinstance(uri_val, dict) and 'Uri' in uri_val and uri_val['Uri'].startswith("rtsp://"):
                                         obtained_uri = uri_val['Uri']; logger.info(f"Using RTSP URI from profile dict attribute '{attr_name}'"); break
                              if not obtained_uri: logger.warning(f"Could not obtain stream URI via GetStreamUri or profile attributes for {self.name}.")

                    if obtained_uri:
                        uri_parts = obtained_uri.split('://')
                        has_embedded_creds = len(uri_parts) > 1 and '@' in uri_parts[1].split('/')[0]
                        if not has_embedded_creds and self.user and self.password:
                            stream_uri = obtained_uri.replace("rtsp://", f"rtsp://{self.user}:{self.password}@", 1)
                            logger.debug(f"Injected resolved credentials into ONVIF URI for {self.name}")
                        else: stream_uri = obtained_uri
                    elif self.url:
                        logger.warning(f"Failed to get stream URI via ONVIF for {self.name}. Falling back to manually configured URL.")
                        stream_uri = self.url
                    else:
                        self._set_error("Failed to obtain a valid stream URI via ONVIF and no fallback URL configured."); self.is_connecting = False; return False

                    try:
                        self.ptz = self.onvif_cam.create_ptz_service()
                        ptz_configs = self.ptz.GetConfigurations()
                        found_ptz_token = None
                        if hasattr(self.media_profile, 'PTZConfiguration') and self.media_profile.PTZConfiguration and \
                           hasattr(self.media_profile.PTZConfiguration, 'token'):
                            profile_ptz_token = self.media_profile.PTZConfiguration.token
                            if any(c.token == profile_ptz_token for c in ptz_configs):
                                found_ptz_token = profile_ptz_token; logger.info(f"Using PTZ config from media profile: {found_ptz_token}")
                        if not found_ptz_token and ptz_configs:
                             found_ptz_token = ptz_configs[0].token; logger.warning(f"Using first available PTZ config: {found_ptz_token}")
                        if found_ptz_token: self.ptz_configuration_token = found_ptz_token
                        else: logger.warning(f"No PTZ configurations found for {self.name}. PTZ disabled."); self.ptz = None
                    except Exception as e_ptz:
                         logger.warning(f"Could not initialize ONVIF PTZ for {self.name}: {type(e_ptz).__name__}. PTZ disabled."); self.ptz = None

                except (Fault, TransportError, RequestsConnectionError, TimeoutError, ConnectionRefusedError, XMLSyntaxError, AttributeError) as e_onvif:
                    self._set_error(f"ONVIF connection failed: {type(e_onvif).__name__}"); logger.debug(f"ONVIF error details: {e_onvif}"); self.is_connecting = False; return False
                except Exception as e_generic:
                    self._set_error(f"General ONVIF connection error: {type(e_generic).__name__}"); logger.error(f"Traceback: {traceback.format_exc()}", exc_info=True); self.is_connecting = False; return False

            if not stream_uri:
                 self._set_error("No valid stream URI available for connection."); self.is_connecting = False; return False

            log_uri = re.sub(r':([^/]+)@', r':****@', stream_uri)
            logger.info(f"Opening video capture for {self.name} at URI: {log_uri}")

            ffmpeg_options = {'rtsp_transport': 'tcp', 'stimeout': '5000000'}
            original_ffmpeg_options = os.environ.get("OPENCV_FFMPEG_CAPTURE_OPTIONS")
            os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = ";".join(f"{k};{v}" for k, v in ffmpeg_options.items())
            logger.debug(f"Set FFMPEG options: {os.environ.get('OPENCV_FFMPEG_CAPTURE_OPTIONS')}")

            try:
                self.cap = cv2.VideoCapture(stream_uri, cv2.CAP_FFMPEG)
                if not self.cap or not self.cap.isOpened():
                    logger.warning(f"VideoCapture failed with TCP hint for {self.name}. Retrying with UDP.")
                    os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = "rtsp_transport;udp;stimeout;5000000"
                    self.cap = cv2.VideoCapture(stream_uri, cv2.CAP_FFMPEG)
                    if not self.cap or not self.cap.isOpened():
                         logger.warning(f"VideoCapture failed with UDP hint for {self.name}. Retrying default.")
                         os.environ.pop("OPENCV_FFMPEG_CAPTURE_OPTIONS", None)
                         self.cap = cv2.VideoCapture(stream_uri, cv2.CAP_FFMPEG)
                         if not self.cap or not self.cap.isOpened():
                              self._set_error(f"Failed to open video stream using cv2.VideoCapture after multiple transport attempts."); self.is_connecting = False; return False
            finally:
                if original_ffmpeg_options is None: os.environ.pop("OPENCV_FFMPEG_CAPTURE_OPTIONS", None)
                else: os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = original_ffmpeg_options
                logger.debug("Cleared/Restored FFMPEG capture options environment variable.")

            self.is_connected = True; self.is_connecting = False; self.last_error = None
            logger.info(f"✅ Successfully connected to camera: {self.name} (Raw: {self.raw_name})")
            self.prev_frame_gray = None
            return True

        except Exception as e:
             self._set_error(f"Unexpected error during connection sequence: {type(e).__name__}")
             logger.error(f"Traceback for connection error ({self.name}): {traceback.format_exc()}")
             self.is_connecting = False
             return False

    def get_frame(self) -> Optional[np.ndarray]:
        if not self.is_connected:
            if not self.connect(): return None
        if self.cap is None or not self.cap.isOpened():
             self._set_error("VideoCapture object became invalid or closed."); return None
        try:
            ret, frame = self.cap.read()
            if not ret or frame is None:
                self._set_error("Frame read failed (stream closed or error)."); return None
            return cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        except cv2.error as e:
             self._set_error(f"OpenCV error during frame read: {e.func}"); return None
        except Exception as e:
            self._set_error(f"Unexpected error reading frame: {type(e).__name__}"); return None

    def detect_motion(self, frame: np.ndarray) -> bool:
        if frame is None or self.motion_threshold <= 0: return False
        try:
            gray = cv2.cvtColor(frame, cv2.COLOR_RGB2GRAY)
            gray = cv2.GaussianBlur(gray, (21, 21), 0)
            if self.prev_frame_gray is None: self.prev_frame_gray = gray; return False
            frame_delta = cv2.absdiff(self.prev_frame_gray, gray)
            thresh = cv2.threshold(frame_delta, 25, 255, cv2.THRESH_BINARY)[1]
            thresh = cv2.dilate(thresh, None, iterations=2)
            self.prev_frame_gray = gray
            contours, _ = cv2.findContours(thresh.copy(), cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            return any(cv2.contourArea(contour) >= self.motion_threshold for contour in contours)
        except cv2.error as e: logger.error(f"OpenCV error during motion detection for {self.name}: {e.err}"); self.prev_frame_gray = None; return False
        except Exception as e: logger.error(f"Unexpected error during motion detection for {self.name}: {e}", exc_info=True); self.prev_frame_gray = None; return False

    def _perform_ptz_action(self, action_func, action_name: str = "PTZ action", *args) -> bool:
        if not self.is_connected or not self.ptz or not self.ptz_configuration_token: return False
        try:
            action_func(self.ptz, self.ptz_configuration_token, *args)
            logger.info(f"{action_name} successful for {self.name}.")
            return True
        except (Fault, TransportError, ConnectionRefusedError, TimeoutError) as e:
            logger.error(f"ONVIF PTZ {action_name} Fault/Error for {self.name}: {type(e).__name__}"); return False
        except Exception as e:
            logger.error(f"General Error during PTZ {action_name} for {self.name}: {e}", exc_info=True); return False

    def move_ptz(self, pan: float, tilt: float, zoom: float):
        def action(ptz_service, token, p, t, z):
            try:
                req = ptz_service.create_type('ContinuousMove')
                req.ProfileToken = token
                Velocity = ptz_service.create_type('PTZVector')
                Velocity.PanTilt = ptz_service.create_type('Vector2D', x=np.clip(p,-1.,1.), y=np.clip(t,-1.,1.))
                Velocity.Zoom = ptz_service.create_type('Vector1D', x=np.clip(z,-1.,1.))
                req.Velocity = Velocity
                ptz_service.ContinuousMove(req)
            except Exception as e: logger.error(f"Error creating PTZ move request for {self.name}: {e}", exc_info=True); raise
        self._perform_ptz_action(action, "Continuous Move", pan, tilt, zoom)

    def stop_ptz(self):
        def action(ptz_service, token):
            try:
                req = ptz_service.create_type('Stop')
                req.ProfileToken = token; req.PanTilt = True; req.Zoom = True
                ptz_service.Stop(req)
            except Exception as e: logger.error(f"Error creating PTZ stop request for {self.name}: {e}", exc_info=True); raise
        self._perform_ptz_action(action, "Stop")

    def release(self):
        logger.debug(f"Releasing resources for camera: {self.name}")
        self.is_connected = False
        self.release_capture()
        self.onvif_cam = None; self.ptz = None; self.media_profile = None; self.password = None

    def __del__(self): self.release()

# --- SIEM Client Implementations ---
class SplunkSIEMClient(SIEMInterface):
    """Handles communication with the Splunk SIEM API."""
    def __init__(self, config: dict):
        super().__init__(config)
        self.query = self.config.get('splunk_query', '')
        self.auth_header_type = self.config.get("auth_header_type", "Bearer")
        self.is_configured = bool(self.api_url and self.auth_token and self.query)
        if self.is_configured:
            logger.info(f"SplunkSIEMClient specific config: AuthType='{self.auth_header_type}', Query set.")
            auth_value = f"{self.auth_header_type} {self.auth_token}"
            if self.auth_header_type.lower() not in ["bearer", "splunk"]:
                 logger.warning(f"Unknown SIEM auth header type '{self.auth_header_type}'. Defaulting to 'Bearer'.")
                 auth_value = f"Bearer {self.auth_token}"
            self.session.headers.update({"Authorization": auth_value})
        else:
            logger.warning("Splunk SIEM Client is not fully configured.")

    def _resolve_common_config(self): super()._resolve_common_config()

    def fetch_alerts(self) -> List[Dict]:
        if not self.is_configured: return []
        export_url = f"{self.api_url.rstrip('/')}/services/search/jobs/export"
        search_query = self.query.strip()
        if not search_query: logger.error("Splunk SIEM Error: Search query is empty."); return []
        if not search_query.lower().startswith(('search ', '|')): search_query = f'search {search_query}'
        payload = {"search": search_query, "output_mode": "json"}
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        logger.info(f"Fetching Splunk SIEM alerts from {self.api_url}...")
        try:
            response = self.session.post(export_url, data=payload, headers=headers, timeout=45, verify=self.verify_ssl, stream=True)
            response.raise_for_status()
            alerts = []
            for line_num, line in enumerate(response.iter_lines(decode_unicode=True, delimiter='\n'), 1):
                 if line:
                    try:
                        alert_data = json.loads(line)
                        if isinstance(alert_data, dict):
                            if 'result' in alert_data and isinstance(alert_data['result'], dict): alerts.append(alert_data['result'])
                            elif '_raw' in alert_data or '_time' in alert_data: alerts.append(alert_data)
                    except json.JSONDecodeError: logger.warning(f"Splunk SIEM: Failed decode line #{line_num}: {line[:150]}...")
                    except Exception as e: logger.error(f"Splunk SIEM: Error processing line #{line_num}: {e}", exc_info=True)
            logger.info(f"Successfully fetched {len(alerts)} Splunk SIEM alerts.")
            return alerts
        except Timeout: logger.error(f"Splunk SIEM Error: Timeout to {self.api_url}."); return []
        except RequestsConnectionError as e: logger.error(f"Splunk SIEM Error: Connection failed to {self.api_url}. Error: {e}"); return []
        except RequestException as e:
            logger.error(f"Splunk SIEM Request Error: {e}")
            if e.response is not None: logger.error(f"Splunk SIEM Response Status: {e.response.status_code} Body: {e.response.text[:500]}...")
            return []
        except Exception as e: logger.error(f"Splunk SIEM Error: Unexpected error: {e}", exc_info=True); return []


class ElasticSIEMClient(SIEMInterface):
    def __init__(self, config: dict):
        super().__init__(config)
        self.index_pattern = self.config.get('elastic_index', 'security-alerts-*')
        self.query_dsl_or_kql = self.config.get('elastic_query_dsl', '{"query":{"match_all":{}}, "size": 100}')
        self.auth_method = self.config.get('elastic_auth_method', 'api_key').lower()
        auth_ok = (self.auth_method == 'api_key' and self.auth_token) or \
                  (self.auth_method == 'basic' and self.username and self.password)
        self.is_configured = bool(self.api_url and auth_ok and self.index_pattern)
        if self.is_configured:
             logger.info(f"ElasticSIEMClient configured: URL={self.api_url}, Index={self.index_pattern}, Auth={self.auth_method}")
             self.session.headers.update({'Content-Type': 'application/json', 'kbn-xsrf': 'true'})
             if self.auth_method == 'api_key': self.session.headers.update({'Authorization': f"ApiKey {self.auth_token}"})
             elif self.auth_method == 'basic': self.session.auth = (self.username, self.password)
        else: logger.warning("Elastic SIEM Client is not fully configured.")

    def _resolve_common_config(self): super()._resolve_common_config()

    def fetch_alerts(self) -> List[Dict]:
        if not self.is_configured: return []
        logger.info(f"Fetching Elasticsearch SIEM alerts from {self.api_url} (Index: {self.index_pattern})...")
        search_url = f"{self.api_url.rstrip('/')}/{self.index_pattern}/_search"
        query_data = self.query_dsl_or_kql
        try:
            response = self.session.post(search_url, data=query_data.encode('utf-8'), verify=self.verify_ssl, timeout=30)
            response.raise_for_status()
            results = response.json()
            alerts = []
            hits = results.get('hits', {}).get('hits', [])
            for hit in hits:
                source_data = hit.get('_source', {})
                timestamp = source_data.get('@timestamp') or source_data.get('event', {}).get('created') or source_data.get('timestamp')
                if not timestamp and 'sort' in hit and isinstance(hit['sort'], list) and len(hit['sort']) > 0:
                    try: timestamp = datetime.datetime.fromtimestamp(hit['sort'][0] / 1000.0).isoformat() + 'Z'
                    except: pass
                alert_entry = {
                    '_time': timestamp or hit.get('_index'),
                    '_raw': json.dumps(source_data),
                    'host': source_data.get('host', {}).get('name') or source_data.get('agent', {}).get('hostname'),
                    'source': hit.get('_index'),
                    'sourcetype': source_data.get('event', {}).get('kind') or source_data.get('event', {}).get('category') or hit.get('_index'),
                    **source_data
                }
                alerts.append(alert_entry)
            logger.info(f"Successfully fetched {len(alerts)} Elasticsearch SIEM alerts.")
            return alerts
        except Timeout: logger.error(f"Elastic SIEM Error: Timeout to {self.api_url}."); return []
        except RequestsConnectionError as e: logger.error(f"Elastic SIEM Error: Connection failed to {self.api_url}. Error: {e}"); return []
        except RequestException as e:
            logger.error(f"Elastic SIEM Request Error: {e}")
            if e.response is not None: logger.error(f"Elastic SIEM Response Status: {e.response.status_code} Body: {e.response.text[:500]}...")
            return []
        except Exception as e: logger.error(f"Elastic SIEM Error: Unexpected error fetching/parsing alerts: {e}", exc_info=True); return []


# --- SOAR Client Implementations ---
class SplunkSOARClient(SOARInterface):
    def __init__(self, config: dict):
        super().__init__(config)
        self.is_configured = bool(self.api_url and self.auth_token)
        if self.is_configured:
             logger.info(f"SplunkSOARClient configured: URL={self.api_url}")
             self.session.headers.update({'ph-auth-token': self.auth_token, 'Content-Type': 'application/json'})
        else: logger.warning("Splunk SOAR Client is not fully configured.")

    def _resolve_common_config(self): super()._resolve_common_config()

    def trigger_action(self, action_name: str, parameters: Dict) -> Dict:
        if not self.is_configured: return {"success": False, "message": "SOAR client not configured."}
        if action_name.lower() == 'run_playbook' and 'playbook_id' in parameters:
            playbook_id = parameters['playbook_id']
            api_endpoint = f"{self.api_url.rstrip('/')}/rest/playbook_run"
            payload = { "playbook_id": playbook_id, "scope": parameters.get("scope", "new"), "container_id": parameters.get("container_id"), "sensitivity": parameters.get("sensitivity", "amber"), }
            payload = {k: v for k, v in payload.items() if v is not None}
            logger.info(f"Triggering Splunk SOAR playbook ID: {playbook_id} with params: {payload}")
            try:
                response = self.session.post(api_endpoint, json=payload, verify=self.verify_ssl, timeout=30)
                response.raise_for_status()
                resp_json = response.json(); success = resp_json.get('success', True); message = resp_json.get('message', 'Playbook run initiated.'); playbook_run_id = resp_json.get('playbook_run_id')
                logger.info(f"Splunk SOAR response: {message} (Run ID: {playbook_run_id})")
                return {"success": success, "message": message, "playbook_run_id": playbook_run_id}
            except RequestException as e:
                error_msg = f"Splunk SOAR API error: {e}";
                if e.response is not None: error_msg += f" | Status: {e.response.status_code} | Body: {e.response.text[:200]}"
                logger.error(error_msg); return {"success": False, "message": f"API Error: {type(e).__name__}"}
            except Exception as e:
                logger.error(f"Unexpected error triggering Splunk SOAR action: {e}", exc_info=True); return {"success": False, "message": f"Unexpected Error: {type(e).__name__}"}
        else:
            msg = f"Unsupported SOAR action '{action_name}' or missing 'playbook_id'."; logger.error(msg); return {"success": False, "message": msg}


class CortexXSOARClient(SOARInterface):
     def __init__(self, config: dict):
        super().__init__(config)
        self.auth_header = self.config.get("auth_header_name", "Authorization")
        self.auth_value_prefix = self.config.get("auth_value_prefix", "")
        self.is_configured = bool(self.api_url and self.auth_token)
        if self.is_configured:
            logger.info(f"CortexXSOARClient configured: URL={self.api_url}")
            self.session.headers.update({ self.auth_header: f"{self.auth_value_prefix}{self.auth_token}".strip(), 'Content-Type': 'application/json', 'Accept': 'application/json' })
        else: logger.warning("Cortex XSOAR Client is not fully configured.")

     def _resolve_common_config(self): super()._resolve_common_config()

     def trigger_action(self, action_name: str, parameters: Dict) -> Dict:
        if not self.is_configured: return {"success": False, "message": "SOAR client not configured."}
        if action_name.lower() == 'create_incident' and 'name' in parameters:
            api_endpoint = f"{self.api_url.rstrip('/')}/incident"
            payload = { "name": parameters.get("name"), "type": parameters.get("incident_type", "Default"), "severity": parameters.get("severity", 2), "owner": parameters.get("owner"), "details": parameters.get("details"), }
            payload = {k: v for k, v in payload.items() if v is not None}
            logger.info(f"Triggering Cortex XSOAR incident creation: {payload.get('name')}")
            try:
                response = self.session.post(api_endpoint, json=payload, verify=self.verify_ssl, timeout=30)
                response.raise_for_status(); resp_json = response.json(); incident_id = resp_json.get('id'); message = f"Incident created successfully (ID: {incident_id})."
                logger.info(f"Cortex XSOAR response: {message}"); return {"success": True, "message": message, "incident_id": incident_id}
            except RequestException as e:
                error_msg = f"Cortex XSOAR API error: {e}";
                if e.response is not None: error_msg += f" | Status: {e.response.status_code} | Body: {e.response.text[:200]}"
                logger.error(error_msg); return {"success": False, "message": f"API Error: {type(e).__name__}"}
            except Exception as e:
                logger.error(f"Unexpected error triggering Cortex XSOAR action: {e}", exc_info=True); return {"success": False, "message": f"Unexpected Error: {type(e).__name__}"}
        else:
            msg = f"Unsupported SOAR action '{action_name}' or missing required parameters."; logger.error(msg); return {"success": False, "message": msg}

# --- SIEM/SOAR Factory Functions ---
SIEM_TYPE_MAP = { "Splunk": SplunkSIEMClient, "Elasticsearch": ElasticSIEMClient, }
SOAR_TYPE_MAP = { "SplunkSOAR": SplunkSOARClient, "CortexXSOAR": CortexXSOARClient, }

def create_siem_client(config: dict) -> Optional[SIEMInterface]:
    if not config.get('enabled', False): logger.info("SIEM integration disabled."); return None
    siem_type = config.get('type')
    if not siem_type: logger.warning("SIEM enabled but no 'type' specified."); return None
    client_class = SIEM_TYPE_MAP.get(siem_type)
    if client_class:
        try:
            logger.info(f"Attempting to create SIEM client: {siem_type}"); client = client_class(config)
            if client.is_configured: logger.info(f"Successfully configured SIEM client: {siem_type}"); return client
            else: logger.warning(f"SIEM client '{siem_type}' failed config check."); return None
        except Exception as e: logger.error(f"Failed to instantiate SIEM client '{siem_type}': {e}", exc_info=True); return None
    else: logger.error(f"Unsupported SIEM type: '{siem_type}'. Available: {list(SIEM_TYPE_MAP.keys())}"); return None

def create_soar_client(config: dict) -> Optional[SOARInterface]:
    if not config.get('enabled', False): logger.info("SOAR integration disabled."); return None
    soar_type = config.get('type')
    if not soar_type: logger.warning("SOAR enabled but no 'type' specified."); return None
    client_class = SOAR_TYPE_MAP.get(soar_type)
    if client_class:
        try:
            logger.info(f"Attempting to create SOAR client: {soar_type}"); client = client_class(config)
            if client.is_configured: logger.info(f"Successfully configured SOAR client: {soar_type}"); return client
            else: logger.warning(f"SOAR client '{soar_type}' failed config check."); return None
        except Exception as e: logger.error(f"Failed to instantiate SOAR client '{soar_type}': {e}", exc_info=True); return None
    else: logger.error(f"Unsupported SOAR type: '{soar_type}'. Available: {list(SOAR_TYPE_MAP.keys())}"); return None

# ==================== SENSOR MONITOR THREAD ====================
class SensorMonitorThread(QThread):
    """Monitors a log file for sensor alerts and emits signals."""
    sensor_alert = pyqtSignal(dict) # Emits full alert data (config + status)

    def __init__(self, sensor_input_config: dict, sensor_definitions: List[Dict], parent=None):
        super().__init__(parent)
        self.config = sensor_input_config
        self.sensor_defs_by_id = {s['id']: s for s in sensor_definitions if 'id' in s}
        self._running = True
        self._log_file_path = self.config.get('path')
        self._interval_ms = self.config.get('read_interval_ms', 2000)
        self._last_pos = 0
        self.setObjectName(f"SensorMonitorThread")
        self.setName(self.objectName())

        if not self._log_file_path:
            logger.error("SensorMonitorThread: Log file path not configured.")
            self._running = False
        else:
            try:
                # Create the file if it doesn't exist to avoid errors later? No, let the external system create it.
                # Check initial readability and find end of file
                if os.path.exists(self._log_file_path):
                    with open(self._log_file_path, 'r', encoding='utf-8') as f:
                        f.seek(0, os.SEEK_END)
                        self._last_pos = f.tell()
                    logger.info(f"SensorMonitorThread initialized. Monitoring: {self._log_file_path}, Interval: {self._interval_ms}ms. Initial position: {self._last_pos}")
                else:
                     logger.warning(f"Sensor log file '{self._log_file_path}' not found initially. Will attempt to read later.")
                     self._last_pos = 0
            except Exception as e:
                 logger.error(f"Error accessing sensor log file '{self._log_file_path}' on init: {e}", exc_info=True)
                 self._running = False

    def run(self):
        logger.info(f"SensorMonitorThread starting ({self._log_file_path})...")
        while self._running:
            try:
                time.sleep(self._interval_ms / 1000.0)
                if not os.path.exists(self._log_file_path): continue

                new_lines = []
                try:
                    current_size = os.path.getsize(self._log_file_path)
                    if current_size < self._last_pos: # Log file truncated or replaced
                        logger.info(f"Sensor log file '{self._log_file_path}' appears truncated/reset. Reading from beginning.")
                        self._last_pos = 0

                    if current_size > self._last_pos:
                        with open(self._log_file_path, 'r', encoding='utf-8') as f:
                            f.seek(self._last_pos)
                            new_lines = f.readlines()
                            self._last_pos = f.tell()
                except FileNotFoundError:
                    logger.warning(f"Sensor log file '{self._log_file_path}' disappeared?")
                    self._last_pos = 0; time.sleep(5); continue
                except Exception as e:
                    logger.error(f"Error reading sensor log file '{self._log_file_path}': {e}")
                    time.sleep(5); continue

                for line in new_lines:
                    line = line.strip()
                    if not line: continue
                    try:
                        log_entry = json.loads(line)
                        sensor_id = log_entry.get('sensor_id')
                        status = log_entry.get('status')
                        timestamp = log_entry.get('timestamp', datetime.datetime.now().isoformat())

                        if not sensor_id or not status:
                             logger.warning(f"Invalid log entry format: {line[:100]}..."); continue

                        sensor_def = self.sensor_defs_by_id.get(sensor_id)
                        if not sensor_def:
                            logger.warning(f"Alert for unknown sensor ID: '{sensor_id}'. Log: {line[:100]}..."); continue

                        alert_payload = { **sensor_def, 'status': status, 'timestamp': timestamp }
                        logger.debug(f"Sensor alert received: ID={sensor_id}, Status={status}")
                        try: self.sensor_alert.emit(alert_payload)
                        except RuntimeError as e: logger.error(f"RuntimeError emitting sensor alert for {sensor_id}. Stopping thread. Error: {e}"); self._running = False; break
                    except json.JSONDecodeError: logger.warning(f"Failed JSON decode: {line[:100]}...")
                    except Exception as e: logger.error(f"Error processing sensor log line '{line[:100]}...': {e}", exc_info=True)
            except Exception as e:
                logger.error(f"Unexpected error in SensorMonitorThread loop: {e}", exc_info=True)
                time.sleep(10)
        logger.info("SensorMonitorThread stopping.")

    def stop(self):
        logger.info("SensorMonitorThread stop requested.")
        self._running = False


# ==================== GUI COMPONENTS ====================
class CameraConfigDialog(QDialog):
    """Dialog for adding or editing camera configurations."""
    def __init__(self, parent=None, config=None):
        super().__init__(parent)
        self.setWindowTitle("Camera Configuration")
        self.setMinimumWidth(450)
        self.original_config = config or {}
        self.config_copy = copy.deepcopy(self.original_config) if self.original_config else {}
        layout = QVBoxLayout(self)
        form_layout = QFormLayout(); form_layout.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        self.name_input = QLineEdit(self.config_copy.get('name', ''))
        self.type_combo = QComboBox(); self.type_combo.addItems(["RTSP URL", "ONVIF"])
        self.url_input = QLineEdit(); self.host_input = QLineEdit(); self.port_input = QLineEdit(str(self.config_copy.get('port', 80)))
        self.user_input = QLineEdit(); self.password_input = QLineEdit(); self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.motion_thresh_input = QLineEdit(str(self.config_copy.get('motion_threshold', 500)))
        def set_line_edit_text(line_edit: QLineEdit, value: Any):
             if isinstance(value, str) and value.startswith("ENV:"): line_edit.setPlaceholderText(f"Using ENV ({value[4:]})"); line_edit.setText("")
             else: line_edit.setText(str(value) if value is not None else "")
        set_line_edit_text(self.url_input, self.config_copy.get('url', 'rtsp://user:pass@host:port/stream'))
        set_line_edit_text(self.host_input, self.config_copy.get('host', '192.168.1.100'))
        self.port_input.setText(str(self.config_copy.get('port', 80)))
        self.motion_thresh_input.setText(str(self.config_copy.get('motion_threshold', 500)))
        set_line_edit_text(self.user_input, self.config_copy.get('user', 'admin'))
        set_line_edit_text(self.password_input, self.config_copy.get('password', ''))
        env_tooltip = "Enter value directly, or use 'ENV:YOUR_VAR_NAME' to read from environment."
        self.url_input.setToolTip(env_tooltip); self.host_input.setToolTip(env_tooltip); self.user_input.setToolTip(env_tooltip); self.password_input.setToolTip(env_tooltip)
        form_layout.addRow("Name*:", self.name_input); form_layout.addRow("Type:", self.type_combo)
        self.url_row_widget = QWidget(); self.url_row_layout = QFormLayout(self.url_row_widget); self.url_row_layout.setContentsMargins(0,0,0,0)
        self.url_label = QLabel("RTSP URL:"); self.url_row_layout.addRow(self.url_label, self.url_input); form_layout.addRow(self.url_row_widget)
        self.onvif_rows_widget = QWidget(); self.onvif_rows_layout = QFormLayout(self.onvif_rows_widget); self.onvif_rows_layout.setContentsMargins(0,0,0,0)
        self.host_label = QLabel("ONVIF Host*:"); self.port_label = QLabel("ONVIF Port*:"); self.user_label = QLabel("ONVIF User:"); self.password_label = QLabel("ONVIF Password:")
        self.onvif_rows_layout.addRow(self.host_label, self.host_input); self.onvif_rows_layout.addRow(self.port_label, self.port_input); self.onvif_rows_layout.addRow(self.user_label, self.user_input); self.onvif_rows_layout.addRow(self.password_label, self.password_input); form_layout.addRow(self.onvif_rows_widget)
        form_layout.addRow("Motion Threshold:", self.motion_thresh_input); self.motion_thresh_input.setToolTip("Contour area threshold (pixels). 0 to disable.")
        layout.addLayout(form_layout)
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel); button_box.accepted.connect(self.accept); button_box.rejected.connect(self.reject); layout.addWidget(button_box)
        self.type_combo.currentIndexChanged.connect(self.update_fields_visibility)
        self.type_combo.setCurrentIndex(1 if self.config_copy.get('onvif', False) else 0); self.update_fields_visibility()

    def update_fields_visibility(self):
        is_onvif = (self.type_combo.currentText() == "ONVIF")
        self.url_row_widget.setVisible(not is_onvif); self.onvif_rows_widget.setVisible(is_onvif)
        self.url_label.setText("RTSP URL*:" if not is_onvif else "RTSP URL:")
        self.host_label.setText("ONVIF Host*:" if is_onvif else "ONVIF Host:")
        self.port_label.setText("ONVIF Port*:" if is_onvif else "ONVIF Port:")
        self.user_label.setText("ONVIF User:" if is_onvif else "ONVIF User:")
        self.password_label.setText("ONVIF Password:" if is_onvif else "ONVIF Password:")

    def get_config(self) -> Optional[Dict]:
        config = {}; config['name'] = self.name_input.text().strip()
        if not config['name']: QMessageBox.warning(self, "Input Error", "Camera Name cannot be empty."); return None
        is_onvif = (self.type_combo.currentText() == "ONVIF"); config['onvif'] = is_onvif
        def get_value_or_env(line_edit: QLineEdit, original_config_value: Optional[str]) -> Optional[str]:
            text = line_edit.text().strip()
            if not text and isinstance(original_config_value, str) and original_config_value.startswith("ENV:"): return original_config_value
            elif text.upper().startswith("ENV:"):
                 var_name = text[4:]
                 if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', var_name): return f"ENV:{var_name}"
                 else: raise ValueError(f"Invalid environment variable format: '{text}'. Use 'ENV:VAR_NAME'.")
            else: return text if text else None
        try:
            if is_onvif:
                config['host'] = get_value_or_env(self.host_input, self.original_config.get('host'))
                if not config['host']: QMessageBox.warning(self, "Input Error", "ONVIF Host cannot be empty."); return None
                try: port_val = int(self.port_input.text().strip()); assert 1 <= port_val <= 65535; config['port'] = port_val
                except: QMessageBox.warning(self, "Input Error", "Invalid ONVIF Port (must be 1-65535)."); return None
                config['user'] = get_value_or_env(self.user_input, self.original_config.get('user'))
                config['password'] = get_value_or_env(self.password_input, self.original_config.get('password'))
                config['url'] = get_value_or_env(self.url_input, self.original_config.get('url'))
                if config['url'] and not config['url'].lower().startswith("rtsp://") and not config['url'].startswith("ENV:"): QMessageBox.warning(self, "Input Error", "Fallback URL for ONVIF must start with rtsp:// or be ENV:"); return None
            else:
                config['url'] = get_value_or_env(self.url_input, self.original_config.get('url'))
                if not config['url']: QMessageBox.warning(self, "Input Error", "RTSP URL cannot be empty."); return None
                if not config['url'].lower().startswith("rtsp://") and not config['url'].startswith("ENV:"): QMessageBox.warning(self, "Input Error", "RTSP URL must start with rtsp:// or be ENV:"); return None
                config['host'] = None; config['port'] = None; config['user'] = None; config['password'] = None
            try: mt_val_str = self.motion_thresh_input.text().strip(); config['motion_threshold'] = int(mt_val_str) if mt_val_str else 0; assert config['motion_threshold'] >= 0
            except: QMessageBox.warning(self, "Input Error", "Motion Threshold must be a non-negative integer."); return None
            return config
        except ValueError as e: QMessageBox.warning(self, "Input Error", str(e)); return None
        except Exception as e: logger.error(f"Error gathering config from dialog: {e}", exc_info=True); QMessageBox.critical(self, "Error", f"Internal error: {e}"); return None


class CameraThread(QThread):
    """Handles video processing for a camera in a separate thread."""
    new_frame = pyqtSignal(str, object) # sanitized_name, frame_object
    motion_detected_signal = pyqtSignal(str) # sanitized_name
    connection_status = pyqtSignal(str, bool, str) # sanitized_name, is_connected, error_message

    def __init__(self, camera: SecurityCamera, parent=None):
        super().__init__(parent)
        self.camera = camera
        self._running = True; self._paused = False
        self._last_emitted_connected_status: Optional[bool] = None
        self._last_emitted_error: Optional[str] = None
        self.setObjectName(f"CameraThread_{self.camera.name}")
        self.setName(self.objectName())
        logger.debug(f"Thread {self.objectName()} initialized.")

    def run(self):
        logger.info(f"CameraThread started for {self.camera.name} (Raw: {self.camera.raw_name})")
        last_status_emit_time = 0; status_emit_interval = 5; target_fps = 15; min_sleep = 0.005
        while self._running:
            if self._paused: time.sleep(0.5); continue
            loop_start_time = time.time(); frame = None
            try:
                frame = self.camera.get_frame()
                conn_status = self.camera.is_connected; error_msg = self.camera.last_error
                status_changed = (conn_status != self._last_emitted_connected_status or error_msg != self._last_emitted_error)
                if status_changed or (time.time() - last_status_emit_time > status_emit_interval):
                    try: self.connection_status.emit(self.camera.name, conn_status, error_msg or "")
                    except RuntimeError as e: logger.warning(f"Error emitting status for {self.camera.name}: {e}"); self._running = False; break
                    self._last_emitted_connected_status = conn_status; self._last_emitted_error = error_msg; last_status_emit_time = time.time()
                if frame is not None:
                    try: self.new_frame.emit(self.camera.name, frame)
                    except RuntimeError as e: logger.warning(f"Error emitting frame for {self.camera.name}: {e}"); self._running = False; break
                    if self.camera.motion_threshold > 0 and self.camera.detect_motion(frame):
                        try: self.motion_detected_signal.emit(self.camera.name)
                        except RuntimeError as e: logger.warning(f"Error emitting motion for {self.camera.name}: {e}"); self._running = False; break
                    processing_time = time.time() - loop_start_time
                    sleep_time = max(min_sleep, (1.0 / target_fps) - processing_time)
                    if sleep_time > 0: time.sleep(sleep_time)
                else: time.sleep(1.0)
            except Exception as e:
                thread_error_msg = f"Unexpected error in CameraThread ({self.camera.name}): {type(e).__name__}"
                logger.error(thread_error_msg + f"\n{traceback.format_exc()}")
                try:
                     if self._last_emitted_error != thread_error_msg:
                         self.connection_status.emit(self.camera.name, False, thread_error_msg)
                         self._last_emitted_connected_status = False; self._last_emitted_error = thread_error_msg; last_status_emit_time = time.time()
                except RuntimeError: pass
                except Exception as emit_err: logger.error(f"Failed to emit thread loop error status for {self.camera.name}: {emit_err}")
                time.sleep(5.0)
        logger.info(f"CameraThread stopping for {self.camera.name}...")
        self.camera.release()
        logger.info(f"CameraThread finished for {self.camera.name}")

    def stop(self): self._running = False
    def pause(self): self._paused = True
    def resume(self): self._paused = False


class NotificationManager(QLabel):
    """A custom label for displaying temporary notifications with animation."""
    def __init__(self, parent):
        super().__init__(parent); self.parent_widget = parent; self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet("QLabel { background-color: rgba(0, 0, 0, 0.8); color: white; border-radius: 6px; padding: 12px 18px; font-size: 10pt; border: 1px solid #555; }")
        self.setWordWrap(True); self.setMinimumWidth(300); self.setMaximumWidth(500); self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.MinimumExpanding); self.hide()
        self.animation = QPropertyAnimation(self, b"geometry", self); self.animation.setDuration(400); self.animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._hide_timer = QTimer(self); self._hide_timer.setSingleShot(True); self._hide_timer.timeout.connect(self.hide_notification); self.animation.finished.connect(self._on_animation_finished)

    def show_message(self, message: str, duration: int = 4000, level: str = "info"):
        self.setText(escape(message))
        base_style = "color: white; border-radius: 6px; padding: 12px 18px; font-size: 10pt;"; level_style = ""
        if level == "error": level_style = "background-color: rgba(231, 76, 60, 0.9); border: 1px solid #c0392b;"
        elif level == "warning": level_style = "background-color: rgba(243, 156, 18, 0.9); border: 1px solid #d35400;"
        elif level == "success": level_style = "background-color: rgba(46, 204, 113, 0.9); border: 1px solid #27ae60;"
        else: level_style = "background-color: rgba(52, 152, 219, 0.9); border: 1px solid #2980b9;"
        self.setStyleSheet(f"QLabel {{ {base_style} {level_style} }}"); self.adjustSize()
        parent_width = self.parent_widget.width(); my_width = self.width(); my_height = self.height(); max_w = parent_width - 40
        if my_width > max_w: my_width = max_w; self.setFixedWidth(my_width)
        start_x = (parent_width - my_width) // 2; start_y = -my_height - 10; end_x = start_x; end_y = 20
        start_geom = QRect(start_x, start_y, my_width, my_height); end_geom = QRect(end_x, end_y, my_width, my_height)
        self.animation.stop(); self._hide_timer.stop(); self.setGeometry(start_geom); self.show(); self.raise_()
        self.animation.setDirection(QPropertyAnimation.Direction.Forward); self.animation.setStartValue(start_geom); self.animation.setEndValue(end_geom); self.animation.start(); self._hide_timer.start(duration)

    def hide_notification(self):
        if not self.isVisible() or (self.animation.state() == QPropertyAnimation.State.Running and self.animation.direction() == QPropertyAnimation.Direction.Backward): return
        start_geom = self.geometry(); end_geom = QRect(start_geom.x(), -start_geom.height() - 10, start_geom.width(), start_geom.height())
        self._hide_timer.stop(); self.animation.stop(); self.animation.setDirection(QPropertyAnimation.Direction.Backward); self.animation.setStartValue(start_geom); self.animation.setEndValue(end_geom); self.animation.start()

    @pyqtSlot()
    def _on_animation_finished(self):
        if self.animation.direction() == QPropertyAnimation.Direction.Backward: self.hide()


# ==================== MAP MARKER ITEM ====================
class MapMarkerItem(QGraphicsPixmapItem):
    """Represents a draggable camera OR sensor icon on the map view."""
    markerClicked = pyqtSignal(str) # Emits item ID (sanitized camera name or sensor ID)
    markerMoved = pyqtSignal(str, QPointF) # Emits item ID and new position

    def __init__(self, item_id: str, item_type: str, icon: QPixmap, position: QPointF, parent_window, parent: QGraphicsItem = None):
        super().__init__(icon, parent)
        self.item_id = item_id
        self.item_type = item_type # 'camera' or 'sensor'
        self.parent_window = parent_window # Reference to main window (for icons)
        self.setPos(position)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)
        self.setAcceptHoverEvents(True)
        self.base_tooltip = f"Sensor: {item_id}" if item_type == 'sensor' else f"Camera: {item_id}"
        self.setToolTip(f"{self.base_tooltip}\nClick to view details/cameras")
        self.setOffset(-icon.width() / 2, -icon.height())
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._is_edit_mode: bool = False
        self._drag_start_pos: QPointF = QPointF()
        self.is_alerting: bool = False
        self.current_severity: str = 'Normal'
        shadow = QGraphicsDropShadowEffect(); shadow.setBlurRadius(8); shadow.setColor(QColor(0, 0, 0, 100)); shadow.setOffset(2, 2); self.setGraphicsEffect(shadow)

    def setEditMode(self, editable: bool):
        if self._is_edit_mode == editable: return
        self._is_edit_mode = editable
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable, editable)
        if editable:
            self.setCursor(Qt.CursorShape.OpenHandCursor)
            self.setToolTip(f"{self.base_tooltip}\nDrag to move")
        else:
            self.setCursor(Qt.CursorShape.PointingHandCursor)
            click_action = "Click to view associated cameras" if self.item_type == 'sensor' else "Click to view camera"
            self.setToolTip(f"{self.base_tooltip}\n{click_action}")

    def setAlertState(self, is_alerting: bool, severity: str):
        """Updates the visual state (icon) of the sensor marker."""
        if self.item_type != 'sensor': return
        new_severity_state = severity if is_alerting else 'Normal'
        if self.is_alerting == is_alerting and self.current_severity == new_severity_state: return

        self.is_alerting = is_alerting
        self.current_severity = new_severity_state
        logger.debug(f"Setting alert state for sensor '{self.item_id}': Alerting={is_alerting}, Severity={self.current_severity}")

        icon_key = 'sensor_normal'
        if is_alerting:
            sev_lower = severity.lower()
            if sev_lower == 'critical': icon_key = 'sensor_alert_critical'
            elif sev_lower == 'high': icon_key = 'sensor_alert_high'
            elif sev_lower == 'medium': icon_key = 'sensor_alert_medium'
            elif sev_lower == 'low': icon_key = 'sensor_alert_low'
            else: icon_key = 'sensor_alert_medium' # Default alert icon

        new_icon = self.parent_window.sensor_icons.get(icon_key)
        if new_icon and not new_icon.isNull():
            self.setPixmap(new_icon)
            self.setOffset(-new_icon.width() / 2, -new_icon.height())
        else: logger.warning(f"Could not find or load icon for key '{icon_key}'")

    def mousePressEvent(self, event: 'QGraphicsSceneMouseEvent'):
        if event.button() == Qt.MouseButton.LeftButton:
            if self._is_edit_mode: self.setCursor(Qt.CursorShape.ClosedHandCursor); self._drag_start_pos = self.pos()
            super().mousePressEvent(event)
        else: event.ignore()

    def mouseMoveEvent(self, event: 'QGraphicsSceneMouseEvent'):
        if self._is_edit_mode and event.buttons() & Qt.MouseButton.LeftButton: super().mouseMoveEvent(event)
        else: event.ignore()

    def mouseReleaseEvent(self, event: 'QGraphicsSceneMouseEvent'):
        if event.button() == Qt.MouseButton.LeftButton:
            if self._is_edit_mode:
                self.setCursor(Qt.CursorShape.OpenHandCursor); new_pos = self.pos()
                if (new_pos - self._drag_start_pos).manhattanLength() > 0.5:
                    logger.debug(f"Marker '{self.item_id}' ({self.item_type}) moved to {new_pos}. Emitting.")
                    self.markerMoved.emit(self.item_id, new_pos)
                self.setToolTip(f"{self.base_tooltip}\nDrag to move")
            else:
                 if (event.screenPos() - event.buttonDownScreenPos(Qt.MouseButton.LeftButton)).manhattanLength() < QApplication.startDragDistance():
                      logger.debug(f"Marker '{self.item_id}' ({self.item_type}) clicked."); self.markerClicked.emit(self.item_id)
            super().mouseReleaseEvent(event)
        else: event.ignore()

    def hoverEnterEvent(self, event: 'QGraphicsSceneHoverEvent'):
        current_pos = self.pos(); base_tooltip_line1 = self.toolTip().split('\n')[0]
        self.setToolTip(f"{base_tooltip_line1}\nPos: ({current_pos.x():.0f}, {current_pos.y():.0f})"); super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event: 'QGraphicsSceneHoverEvent'):
        if self._is_edit_mode: self.setToolTip(f"{self.base_tooltip}\nDrag to move")
        else:
            click_action = "Click to view associated cameras" if self.item_type == 'sensor' else "Click to view camera"
            self.setToolTip(f"{self.base_tooltip}\n{click_action}")
        super().hoverLeaveEvent(event)

    def itemChange(self, change: QGraphicsItem.GraphicsItemChange, value: Any) -> Any:
        if self._is_edit_mode and change == QGraphicsItem.GraphicsItemChange.ItemPositionChange and self.scene():
            new_pos = value; scene_rect = self.scene().sceneRect()
            if scene_rect.isValid() and scene_rect.width() > 0 and scene_rect.height() > 0:
                item_rect = self.boundingRect(); half_width = item_rect.width() / 2; full_height = item_rect.height()
                constrained_x = max(scene_rect.left() + half_width, min(new_pos.x(), scene_rect.right() - half_width))
                constrained_y = max(scene_rect.top() + full_height, min(new_pos.y(), scene_rect.bottom()))
                return QPointF(constrained_x, constrained_y)
            else: return value
        return super().itemChange(change, value)


# ==================== MFA/2FA DIALOGS ====================
class TOTPVerificationDialog(QDialog):
    """Dialog to prompt for TOTP code at startup or for actions."""
    def __init__(self, parent=None, prompt_message="Enter 2FA Code:", use_recovery=False):
        super().__init__(parent)
        self.setWindowTitle("Two-Factor Authentication Required"); self.setModal(True); self.setMinimumWidth(350)
        layout = QVBoxLayout(self); self.prompt_label = QLabel(prompt_message); self.prompt_label.setWordWrap(True); layout.addWidget(self.prompt_label)
        self.code_input = QLineEdit(); self.code_input.setPlaceholderText("Enter 6-digit code or recovery code"); self.code_input.setMaxLength(30); self.code_input.setMinimumHeight(30); self.code_input.setStyleSheet("font-size: 14pt; letter-spacing: 3px;"); layout.addWidget(self.code_input)
        self.status_label = QLabel(""); self.status_label.setStyleSheet("color: red;"); layout.addWidget(self.status_label)
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel); button_box.accepted.connect(self.accept); button_box.rejected.connect(self.reject); layout.addWidget(button_box)
        self.ok_button = button_box.button(QDialogButtonBox.StandardButton.Ok); self.ok_button.setEnabled(False); self.code_input.textChanged.connect(self._check_input)
        self.secret: Optional[str] = None; self.verification_successful: bool = False; self.use_recovery = use_recovery
        try:
            self.secret = get_totp_secret()
            if not self.secret and not self.use_recovery:
                 try:
                     if get_recovery_codes(): logger.info("TOTP secret missing, but recovery codes exist."); self.prompt_label.setText("Authenticator secret missing. Enter a Recovery Code:")
                     else: self.prompt_label.setText("Error: MFA required, but secret key & recovery codes missing."); self.code_input.setEnabled(False); self.ok_button.setEnabled(False)
                 except KeyringError: self.prompt_label.setText("Error: MFA required, secret missing, recovery check failed."); self.code_input.setEnabled(False); self.ok_button.setEnabled(False)
        except KeyringError as e: self.prompt_label.setText(f"Keyring Error: {e}."); self.code_input.setEnabled(False); self.ok_button.setEnabled(False)
        except Exception as e: self.prompt_label.setText(f"Unexpected error: {e}"); self.code_input.setEnabled(False); self.ok_button.setEnabled(False)

    def _check_input(self, text): self.ok_button.setEnabled(len(text.strip()) >= 6); self.status_label.setText("")

    def accept(self):
        entered_code = self.code_input.text().strip(); is_valid = False
        if not self.use_recovery:
            if self.secret and verify_totp_code(self.secret, entered_code): logger.info("MFA verification successful (TOTP)."); is_valid = True
            else:
                if use_recovery_code(entered_code): logger.info("MFA verification successful (Recovery Code)."); is_valid = True
                else: self.status_label.setText("Invalid code."); logger.warning("MFA verification failed: Invalid TOTP or Recovery Code.")
        else:
             if use_recovery_code(entered_code): logger.info("Recovery code validation successful."); is_valid = True
             else: self.status_label.setText("Invalid recovery code."); logger.warning("Recovery code validation failed.")
        if is_valid: self.verification_successful = True; super().accept()
        else: self.code_input.setFocus(); self.code_input.selectAll()

    def reject(self): logger.warning("MFA verification cancelled."); self.verification_successful = False; super().reject()


class MFASetupDialog(QDialog):
    """Dialog for setting up and managing MFA/2FA."""
    def __init__(self, parent=None):
        super().__init__(parent); self.setWindowTitle("Manage Two-Factor Authentication (MFA/2FA)"); self.setMinimumWidth(550)
        self.main_layout = QVBoxLayout(self); self.stacked_widget = QWidget(); self.main_layout.addWidget(self.stacked_widget)
        self.current_secret: Optional[str] = None; self.new_secret: Optional[str] = None; self.new_recovery_codes: Optional[List[str]] = None
        self.status_label = QLabel("")
        # --- Setup State Widgets ---
        self.setup_widget = QWidget(); setup_layout = QVBoxLayout(self.setup_widget); setup_layout.addWidget(QLabel("<h2>Setup Two-Factor Authentication</h2>")); setup_layout.addWidget(QLabel("1. Install an authenticator app...")); setup_layout.addWidget(QLabel("2. Scan the QR code or enter the secret key..."))
        qr_secret_layout = QHBoxLayout(); self.qr_code_label = QLabel("Generating QR Code..."); self.qr_code_label.setFixedSize(200, 200); self.qr_code_label.setAlignment(Qt.AlignmentFlag.AlignCenter); self.qr_code_label.setStyleSheet("border: 1px solid #888; background-color: white;"); qr_secret_layout.addWidget(self.qr_code_label)
        secret_layout = QVBoxLayout(); secret_layout.addWidget(QLabel("<b>Secret Key:</b>")); self.secret_key_display = QLineEdit(); self.secret_key_display.setReadOnly(True); self.secret_key_display.setStyleSheet("font-family: monospace; font-size: 10pt;"); copy_secret_btn = QPushButton("Copy"); copy_secret_btn.clicked.connect(self._copy_secret); secret_h_layout = QHBoxLayout(); secret_h_layout.addWidget(self.secret_key_display); secret_h_layout.addWidget(copy_secret_btn); secret_layout.addLayout(secret_h_layout); secret_layout.addStretch(); qr_secret_layout.addLayout(secret_layout); setup_layout.addLayout(qr_secret_layout)
        setup_layout.addWidget(QLabel("3. Enter the 6-digit code to verify setup:")); self.verify_code_input = QLineEdit(); self.verify_code_input.setPlaceholderText("Enter 6-digit code"); self.verify_code_input.setMaxLength(7); setup_layout.addWidget(self.verify_code_input)
        self.setup_status_label = QLabel(" "); self.setup_status_label.setStyleSheet("color: red;"); setup_layout.addWidget(self.setup_status_label)
        setup_buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel); self.enable_button = setup_buttons.button(QDialogButtonBox.StandardButton.Ok); self.enable_button.setText("Verify & Enable"); self.enable_button.clicked.connect(self._verify_and_enable); setup_buttons.rejected.connect(self.reject); setup_layout.addWidget(setup_buttons)
        # --- Recovery Code Display Widgets ---
        self.recovery_widget = QWidget(); recovery_layout = QVBoxLayout(self.recovery_widget); recovery_layout.addWidget(QLabel("<h2>Recovery Codes</h2>")); recovery_layout.addWidget(QLabel("<font color='orange'><b>IMPORTANT:</b></font> Store these codes securely...")); self.recovery_codes_display = QPlainTextEdit(); self.recovery_codes_display.setReadOnly(True); self.recovery_codes_display.setMinimumHeight(150); self.recovery_codes_display.setStyleSheet("font-family: monospace; font-size: 11pt;"); recovery_layout.addWidget(self.recovery_codes_display)
        recovery_buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok); recovery_buttons.accepted.connect(self.accept); recovery_buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Done (I have saved these!)"); recovery_layout.addWidget(recovery_buttons)
        # --- Enabled State Widgets ---
        self.enabled_widget = QWidget(); enabled_layout = QVBoxLayout(self.enabled_widget); enabled_layout.addWidget(QLabel("<h2>Two-Factor Authentication is Enabled</h2>")); self.view_recovery_btn = QPushButton("View Recovery Codes"); self.view_recovery_btn.setToolTip("Requires current 2FA code verification."); self.view_recovery_btn.clicked.connect(self._show_recovery_codes); enabled_layout.addWidget(self.view_recovery_btn); enabled_layout.addSpacing(15); self.disable_mfa_btn = QPushButton("Disable 2FA"); self.disable_mfa_btn.setToolTip("Requires current 2FA code verification."); self.disable_mfa_btn.clicked.connect(self._disable_mfa); enabled_layout.addWidget(self.disable_mfa_btn); enabled_layout.addSpacing(20); close_button = QPushButton("Close"); close_button.clicked.connect(self.accept); enabled_layout.addWidget(close_button, 0, Qt.AlignmentFlag.AlignRight)
        self._check_current_mfa_status()

    def _check_current_mfa_status(self):
        current_layout = self.stacked_widget.layout()
        if current_layout:
             while item := current_layout.takeAt(0):
                 if widget := item.widget(): widget.setParent(None); widget.deleteLater()
             QWidget().setLayout(current_layout)
        try:
            self.current_secret = get_totp_secret()
            layout = QVBoxLayout(self.stacked_widget)
            if self.current_secret: logger.info("MFA Setup Dialog: MFA is ENABLED."); layout.addWidget(self.enabled_widget)
            else: logger.info("MFA Setup Dialog: MFA is DISABLED."); self._prepare_setup_state(); layout.addWidget(self.setup_widget)
            self.stacked_widget.setLayout(layout)
        except KeyringError as e: logger.error(f"MFA Setup Dialog: Keyring error: {e}"); QMessageBox.critical(self, "Keyring Error", f"Keyring error:\n{e}"); self.reject()
        except Exception as e: logger.error(f"MFA Setup Dialog: Unexpected error: {e}", exc_info=True); QMessageBox.critical(self, "Error", f"Unexpected error:\n{e}"); self.reject()

    def _prepare_setup_state(self):
        self.new_secret = pyotp.random_base32(length=32); self.new_recovery_codes = [f"{pyotp.random_base32(10)[:5]}-{pyotp.random_base32(10)[5:]}" for _ in range(NUM_RECOVERY_CODES)]; self.secret_key_display.setText(self.new_secret)
        try:
            issuer_name = "SecurityMonitorPro"; user_identifier = os.getlogin() if hasattr(os, 'getlogin') else platform.node() or "user"
            provisioning_uri = pyotp.totp.TOTP(self.new_secret).provisioning_uri(name=user_identifier, issuer_name=issuer_name)
            qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=5, border=4); qr.add_data(provisioning_uri); qr.make(fit=True); img = qr.make_image(fill_color="black", back_color="white")
            buffer = io.BytesIO(); img.save(buffer, "PNG"); buffer.seek(0); pixmap = QPixmap(); pixmap.loadFromData(buffer.read(), "PNG"); self.qr_code_label.setPixmap(pixmap.scaled(200, 200, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        except Exception as e: logger.error(f"Failed to generate QR code: {e}", exc_info=True); self.qr_code_label.setText("Error generating QR code.")
        self.verify_code_input.clear(); self.setup_status_label.setText(" ")

    def _copy_secret(self):
        if self.new_secret: QApplication.clipboard().setText(self.new_secret); self.setup_status_label.setText("<font color='green'>Secret copied!</font>"); QTimer.singleShot(2000, lambda: self.setup_status_label.setText(" "))

    def _verify_and_enable(self):
        entered_code = self.verify_code_input.text().strip()
        if not self.new_secret or not self.new_recovery_codes: self.setup_status_label.setText("Error: No secret generated."); return
        if verify_totp_code(self.new_secret, entered_code):
            logger.info("Setup verification successful.");
            try:
                set_totp_secret(self.new_secret); store_recovery_codes(self.new_recovery_codes)
                self.recovery_codes_display.setPlainText("\n".join(self.new_recovery_codes))
                current_layout = self.stacked_widget.layout();
                if current_layout:
                    while item := current_layout.takeAt(0):
                         if widget := item.widget(): widget.setParent(None)
                    QWidget().setLayout(current_layout)
                layout = QVBoxLayout(self.stacked_widget); layout.addWidget(self.recovery_widget); self.stacked_widget.setLayout(layout)
                logger.info("MFA Enabled Successfully.")
            except KeyringError as e: logger.error(f"Keyring error enabling MFA: {e}"); self.setup_status_label.setText(f"Keyring Error: {e}"); try: delete_totp_secret(); delete_recovery_codes() except: pass
            except Exception as e: logger.error(f"Error enabling MFA: {e}", exc_info=True); self.setup_status_label.setText(f"Error: {e}")
        else: self.setup_status_label.setText("Verification failed."); logger.warning("MFA setup verification failed."); self.verify_code_input.setFocus(); self.verify_code_input.selectAll()

    def _show_recovery_codes(self):
        logger.debug("Attempting to show recovery codes.")
        verifier = TOTPVerificationDialog(self, "Enter current 2FA code or a Recovery Code:", use_recovery=True)
        if verifier.exec() == QDialog.DialogCode.Accepted and verifier.verification_successful:
            try:
                codes = get_recovery_codes()
                if codes:
                    self.recovery_codes_display.setPlainText("\n".join(codes))
                    current_layout = self.stacked_widget.layout()
                    if current_layout:
                        while item := current_layout.takeAt(0):
                             if widget := item.widget(): widget.setParent(None)
                        QWidget().setLayout(current_layout)
                    layout = QVBoxLayout(self.stacked_widget); layout.addWidget(self.recovery_widget); self.stacked_widget.setLayout(layout)
                else: QMessageBox.warning(self, "Recovery Codes", "No recovery codes found.")
            except KeyringError as e: QMessageBox.critical(self, "Keyring Error", f"Failed to retrieve codes:\n{e}")
            except Exception as e: QMessageBox.critical(self, "Error", f"Error retrieving codes:\n{e}")
        elif not verifier.verification_successful: QMessageBox.warning(self, "Verification Failed", "Incorrect code entered.")

    def _disable_mfa(self):
        logger.debug("Attempting to disable MFA.")
        reply = QMessageBox.warning(self, "Disable MFA", "Disable Two-Factor Authentication?\nThis will reduce security.", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Cancel)
        if reply != QMessageBox.StandardButton.Yes: return
        verifier = TOTPVerificationDialog(self, "Enter current 2FA code or a Recovery Code:", use_recovery=True)
        if verifier.exec() == QDialog.DialogCode.Accepted and verifier.verification_successful:
            try:
                delete_totp_secret(); delete_recovery_codes(); logger.info("MFA Disabled Successfully.")
                QMessageBox.information(self, "MFA Disabled", "Two-Factor Authentication disabled.")
                self.accept()
            except KeyringError as e: QMessageBox.critical(self, "Keyring Error", f"Failed to disable MFA:\n{e}")
            except Exception as e: QMessageBox.critical(self, "Error", f"Error disabling MFA:\n{e}")
        elif not verifier.verification_successful: QMessageBox.warning(self, "Verification Failed", "Incorrect code. MFA not disabled.")


# ==================== SENSOR CONFIG DIALOG ====================
class SensorConfigDialog(QDialog):
    """Dialog for adding or editing sensor configurations."""
    def __init__(self, parent=None, config=None, existing_sensor_ids=None, available_cameras=None):
        super().__init__(parent)
        self.setWindowTitle("Sensor Configuration"); self.setMinimumWidth(500)
        self.original_config = config or {}; self.config_copy = copy.deepcopy(self.original_config) if self.original_config else {}
        self.existing_ids = existing_sensor_ids or set(); self.available_cameras = available_cameras or []
        self.is_editing = bool(self.original_config.get('id'))
        layout = QVBoxLayout(self); form_layout = QFormLayout(); form_layout.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        self.id_input = QLineEdit(self.config_copy.get('id', '')); self.id_input.setToolTip("Unique internal identifier (alphanumeric, _, -). Cannot change after creation."); self.id_input.setReadOnly(self.is_editing);
        if not self.is_editing: self.id_input.setPlaceholderText("e.g., FenceNorth01")
        self.name_input = QLineEdit(self.config_copy.get('name', '')); self.name_input.setToolTip("User-friendly display name.")
        self.type_combo = QComboBox(); self.type_combo.addItems(["Motion", "Contact", "Vibration", "Other"]); self.type_combo.setCurrentText(self.config_copy.get('type', 'Motion'))
        self.severity_combo = QComboBox(); self.severity_combo.addItems(["Low", "Medium", "High", "Critical"]); self.severity_combo.setCurrentText(self.config_copy.get('severity', 'Medium'))
        location_layout = QHBoxLayout(); location_layout.setSpacing(5); self.loc_x_spinbox = QDoubleSpinBox(); self.loc_x_spinbox.setRange(-10000, 10000); self.loc_x_spinbox.setDecimals(1); self.loc_x_spinbox.setSingleStep(10.0); self.loc_y_spinbox = QDoubleSpinBox(); self.loc_y_spinbox.setRange(-10000, 10000); self.loc_y_spinbox.setDecimals(1); self.loc_y_spinbox.setSingleStep(10.0)
        loc_x_val = self.config_copy.get('location', {}).get('x', 50.0); loc_y_val = self.config_copy.get('location', {}).get('y', 50.0)
        try: self.loc_x_spinbox.setValue(float(loc_x_val))
        except: self.loc_x_spinbox.setValue(50.0)
        try: self.loc_y_spinbox.setValue(float(loc_y_val))
        except: self.loc_y_spinbox.setValue(50.0)
        location_layout.addWidget(QLabel("X:")); location_layout.addWidget(self.loc_x_spinbox); location_layout.addWidget(QLabel("Y:")); location_layout.addWidget(self.loc_y_spinbox); location_layout.addStretch()
        self.assoc_cameras_list = QListWidget(); self.assoc_cameras_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection); self.assoc_cameras_list.setToolTip("Select cameras visually associated with this sensor."); self.assoc_cameras_list.setMinimumHeight(100); self._populate_camera_list()
        form_layout.addRow("Sensor ID*:", self.id_input); form_layout.addRow("Display Name*:", self.name_input); form_layout.addRow("Sensor Type:", self.type_combo); form_layout.addRow("Default Severity:", self.severity_combo); form_layout.addRow("Map Location (X, Y):", location_layout); form_layout.addRow("Associated Cameras:", self.assoc_cameras_list)
        layout.addLayout(form_layout); button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel); button_box.accepted.connect(self.accept); button_box.rejected.connect(self.reject); layout.addWidget(button_box)

    def _populate_camera_list(self):
        self.assoc_cameras_list.clear(); associated_sanitized_names = set(self.config_copy.get('associated_cameras', [])); self.camera_name_map = {}
        for cam_config in self.available_cameras:
            raw_name = cam_config.get('name'); sanitized_name = sanitize_filename(raw_name)
            if not raw_name: continue; self.camera_name_map[sanitized_name] = raw_name
            item = QListWidgetItem(f" {raw_name}"); item.setData(Qt.ItemDataRole.UserRole, sanitized_name); self.assoc_cameras_list.addItem(item)
            if sanitized_name in associated_sanitized_names: item.setSelected(True)

    def get_config(self) -> Optional[Dict]:
        config = {}; sensor_id = self.id_input.text().strip()
        if not sensor_id: QMessageBox.warning(self, "Input Error", "Sensor ID cannot be empty."); return None
        if not re.match(r'^[a-zA-Z0-9_-]+$', sensor_id): QMessageBox.warning(self, "Input Error", "Sensor ID can only contain letters, numbers, _, -."); return None
        if not self.is_editing and sensor_id in self.existing_ids: QMessageBox.warning(self, "Input Error", f"Sensor ID '{sensor_id}' already exists."); return None
        config['id'] = sensor_id; config['name'] = self.name_input.text().strip()
        if not config['name']: QMessageBox.warning(self, "Input Error", "Display Name cannot be empty."); return None
        config['type'] = self.type_combo.currentText(); config['severity'] = self.severity_combo.currentText(); config['location'] = {'x': self.loc_x_spinbox.value(), 'y': self.loc_y_spinbox.value()}
        selected_cameras_sanitized = [item.data(Qt.ItemDataRole.UserRole) for item in self.assoc_cameras_list.selectedItems() if item.data(Qt.ItemDataRole.UserRole)]
        config['associated_cameras'] = selected_cameras_sanitized
        return config


# ==================== MAIN APPLICATION WINDOW ====================
class SecurityMonitorApp(QMainWindow):
    """Main application window integrating all components."""
    def __init__(self):
        super().__init__(); logger.info("Initializing SecurityMonitorApp...")
        self.setWindowTitle("Security Monitor Pro (Versatile + Sensors)"); self.setGeometry(100, 100, 1500, 950); self.setMinimumSize(1000, 700)
        self._default_app_icon: Optional[QIcon] = self._create_default_icon("app"); self._default_camera_icon: Optional[QPixmap] = self._create_default_icon("camera")
        if self._default_app_icon: self.setWindowIcon(self._default_app_icon)
        self.config_filepath: str = "config.yaml"; self.app_config: Dict[str, Any] = {}; self._settings_dirty: bool = False
        self.cameras: Dict[str, SecurityCamera] = {}; self.camera_threads: Dict[str, CameraThread] = {}; self.video_widgets: Dict[str, QLabel] = {}; self.status_labels: Dict[str, QLabel] = {}; self.motion_indicators: Dict[str, QLabel] = {}; self.camera_group_boxes: Dict[str, QGroupBox] = {}; self.ptz_control_widgets: Dict[str, QWidget] = {}
        self.sensor_definitions: List[Dict] = []; self.sensor_states: Dict[str, Dict] = {}; self.sensor_monitor_thread: Optional[SensorMonitorThread] = None; self.sensor_icons: Dict[str, QPixmap] = {}
        self.map_scene: Optional[QGraphicsScene] = None; self.map_view: Optional[QGraphicsView] = None; self.map_background_item: Optional[QGraphicsPixmapItem] = None; self.map_markers: Dict[str, MapMarkerItem] = {}; self.map_edit_mode: bool = False
        self.siem_client: Optional[SIEMInterface] = None; self.soar_client: Optional[SOARInterface] = None; self.siem_refresh_timer = QTimer(self); self.siem_refresh_timer.timeout.connect(self.refresh_alerts)
        self.load_config(self.config_filepath); self._create_sensor_icons(); self.init_ui(); self.apply_dark_theme(self); self.init_system(); self.update_siem_timer_interval(); logger.info("SecurityMonitorApp initialization complete.")

    def update_siem_timer_interval(self):
         siem_conf = self.app_config.get('siem', {})
         if not siem_conf.get('enabled', False): self.siem_refresh_timer.stop(); logger.info("SIEM auto-refresh disabled."); return
         interval_min = siem_conf.get("refresh_interval_min", 15)
         try: interval_min = max(0, min(int(interval_min), 1440)); siem_conf['refresh_interval_min'] = interval_min; interval_ms = interval_min * 60 * 1000; self.siem_refresh_timer.stop()
              if interval_ms > 0: self.siem_refresh_timer.start(interval_ms); logger.info(f"SIEM timer started. Interval: {interval_min} min.")
              else: logger.info("SIEM auto-refresh disabled (interval 0).")
              if hasattr(self, 'siem_refresh_input'): self.siem_refresh_input.setText(str(interval_min))
         except (ValueError, TypeError): logger.warning(f"Invalid SIEM refresh interval: '{interval_min}'. Setting to 0."); siem_conf['refresh_interval_min'] = 0; self.siem_refresh_timer.stop();
              if hasattr(self, 'siem_refresh_input'): self.siem_refresh_input.setText("0")

    def _create_default_icon(self, type: str = "app") -> Optional[Union[QIcon, QPixmap]]:
        try:
            if type == "camera": pix = QPixmap(24, 24); pix.fill(Qt.GlobalColor.transparent); p = QPainter(pix); p.setRenderHint(QPainter.RenderHint.Antialiasing); p.setBrush(QColor(210, 210, 210)); p.setPen(QPen(Qt.GlobalColor.black, 1)); p.drawRoundedRect(QRectF(2.5, 5.5, 19, 13), 3, 3); p.setBrush(QColor(60, 60, 60)); p.setPen(Qt.PenStyle.NoPen); p.drawEllipse(QRectF(7.5, 8.5, 9, 7)); p.end(); return pix
            else: pixmap = QPixmap(32, 32); pixmap.fill(Qt.GlobalColor.transparent); painter = QPainter(pixmap); painter.setRenderHint(QPainter.RenderHint.Antialiasing); painter.setPen(QPen(QColor(180, 180, 180), 2)); painter.setBrush(QColor(70, 70, 70)); painter.drawRoundedRect(QRectF(3.5, 3.5, 25, 25), 5, 5); painter.setPen(QPen(QColor(60, 180, 230), 3)); painter.drawLine(QPointF(8, 16), QPointF(24, 16)); painter.drawPoint(QPointF(16, 11)); painter.end(); return QIcon(pixmap)
        except Exception as e: logger.error(f"Error creating default '{type}' icon: {e}"); return None

    def _create_sensor_icons(self):
        logger.debug("Creating sensor icons..."); self.sensor_icons = {}
        size = 18; try:
            pix_norm = QPixmap(size, size); pix_norm.fill(Qt.GlobalColor.transparent); p_norm = QPainter(pix_norm); p_norm.setRenderHint(QPainter.RenderHint.Antialiasing); p_norm.setBrush(QColor(120, 120, 120)); p_norm.setPen(QPen(Qt.GlobalColor.black, 1)); p_norm.drawEllipse(QRectF(1.5, 1.5, size-3, size-3)); p_norm.end(); self.sensor_icons['sensor_normal'] = pix_norm
            colors = {'sensor_alert_low': QColor(255, 255, 0), 'sensor_alert_medium': QColor(255, 165, 0), 'sensor_alert_high': QColor(255, 69, 0), 'sensor_alert_critical': QColor(220, 20, 60)}
            for key, color in colors.items():
                pix_alert = QPixmap(size, size); pix_alert.fill(Qt.GlobalColor.transparent); p_alert = QPainter(pix_alert); p_alert.setRenderHint(QPainter.RenderHint.Antialiasing); p_alert.setBrush(color); p_alert.setPen(QPen(color.darker(150), 1)); p_alert.drawEllipse(QRectF(1.5, 1.5, size-3, size-3)); p_alert.end(); self.sensor_icons[key] = pix_alert
            logger.info(f"Created {len(self.sensor_icons)} sensor icons.")
        except Exception as e:
            logger.error(f"Error creating sensor icons: {e}", exc_info=True); fallback_icon = self._create_default_icon("camera")
            if fallback_icon:
                 for key in ['sensor_normal', 'sensor_alert_low', 'sensor_alert_medium', 'sensor_alert_high', 'sensor_alert_critical']: self.sensor_icons.setdefault(key, fallback_icon)

    def load_config(self, filepath: str):
        logger.info(f"Attempting to load configuration from: {filepath}")
        default_config = { "cameras": [], "siem": { "enabled": False, "type": "Splunk", "api_url": "", "auth_token": "", "username": "", "password": "", "auth_header_type": "Bearer", "verify_ssl": True, "refresh_interval_min": 15, "splunk_query": "search index=main earliest=-1h | head 100", "elastic_index": "security-alerts-*", "elastic_query_dsl": '{"query":{"match_all":{}}, "size": 100}', "elastic_auth_method": "api_key" }, "soar": { "enabled": False, "type": "SplunkSOAR", "api_url": "", "auth_token": "", "verify_ssl": True, "auth_header_name": "Authorization", "auth_value_prefix": "" }, "map_view": {"image_path": None, "item_positions": {}}, "fence_sensors": [], "sensor_input": { "enabled": False, "type": "logfile", "path": "sensor_alerts.log", "read_interval_ms": 2000 } }
        if not os.path.exists(filepath):
             logger.warning(f"Config file '{filepath}' not found. Using defaults and attempting to save."); self.app_config = copy.deepcopy(default_config); self._validate_and_correct_config()
             try: self.save_config(filepath)
             except Exception as e: logger.error(f"Failed to save initial default config to {filepath}: {e}")
             return
        if platform.system() != "Windows":
             try: permissions = oct(os.stat(filepath).st_mode)[-3:];
                  if int(permissions[1:]) > 0: logger.warning(f"SECURITY WARNING: Config file '{filepath}' permissions ({permissions}) seem too open. Recommend 600.")
             except Exception as e: logger.warning(f"Could not check permissions for '{filepath}': {e}")
        self.config_filepath = filepath
        try:
            with open(filepath, 'r', encoding='utf-8') as f: loaded_config = yaml.safe_load(f)
            if loaded_config and isinstance(loaded_config, dict):
                def merge_dicts(default, loaded):
                     merged = copy.deepcopy(default);
                     for key, value in loaded.items():
                         if key in merged and isinstance(merged[key], dict) and isinstance(value, dict): merged[key] = merge_dicts(merged[key], value)
                         elif key == "camera_positions" and "item_positions" in merged: # Migration
                              if isinstance(value, dict): merged["item_positions"].update(value); logger.info("Migrated 'camera_positions' to 'item_positions'.")
                         else: merged[key] = value
                     return merged
                self.app_config = merge_dicts(default_config, loaded_config); logger.info(f"Config loaded and merged from {filepath}")
                self._validate_and_correct_config()
            elif loaded_config is None: logger.warning(f"Config file {filepath} is empty. Using defaults."); self.app_config = copy.deepcopy(default_config); self._validate_and_correct_config()
            else: logger.error(f"Config file {filepath} structure invalid. Using defaults."); self.app_config = copy.deepcopy(default_config); self._validate_and_correct_config()
        except yaml.YAMLError as e: logger.error(f"Error parsing config file {filepath}: {e}", exc_info=True); QMessageBox.critical(self, "Config Error", f"Error parsing config:\n{filepath}\n\nInvalid YAML. Using defaults."); self.app_config = copy.deepcopy(default_config); self._validate_and_correct_config()
        except Exception as e: logger.error(f"Error loading config from {filepath}: {e}", exc_info=True); QMessageBox.critical(self, "Config Error", f"Error loading config:\n{filepath}\n\nError: {e}\nUsing defaults."); self.app_config = copy.deepcopy(default_config); self._validate_and_correct_config()

    def _validate_and_correct_config(self):
        logger.debug("Validating configuration...")
        if not isinstance(self.app_config.get('cameras'), list): self.app_config['cameras'] = []
        if not isinstance(self.app_config.get('siem'), dict): self.app_config['siem'] = {}
        if not isinstance(self.app_config.get('soar'), dict): self.app_config['soar'] = {}
        if not isinstance(self.app_config.get('map_view'), dict): self.app_config['map_view'] = {}
        if not isinstance(self.app_config.get('fence_sensors'), list): self.app_config['fence_sensors'] = []
        if not isinstance(self.app_config.get('sensor_input'), dict): self.app_config['sensor_input'] = {}
        # SIEM/SOAR validation (same as before)
        siem_conf = self.app_config['siem']; siem_conf['enabled'] = bool(siem_conf.get('enabled', False)); siem_conf['type'] = str(siem_conf.get('type', 'Splunk')); siem_conf['verify_ssl'] = bool(siem_conf.get('verify_ssl', True)); try: interval = int(siem_conf.get('refresh_interval_min', 15)); siem_conf['refresh_interval_min'] = max(0, min(interval, 1440)) except (ValueError, TypeError): siem_conf['refresh_interval_min'] = 15; siem_conf.setdefault('api_url', None); siem_conf.setdefault('auth_token', None); siem_conf.setdefault('username', None); siem_conf.setdefault('password', None); siem_conf.setdefault('auth_header_type', 'Bearer'); siem_conf.setdefault('splunk_query', ""); siem_conf.setdefault('elastic_index', "security-alerts-*"); siem_conf.setdefault('elastic_query_dsl', '{"query":{"match_all":{}}, "size": 100}'); siem_conf.setdefault('elastic_auth_method', 'api_key')
        soar_conf = self.app_config['soar']; soar_conf['enabled'] = bool(soar_conf.get('enabled', False)); soar_conf['type'] = str(soar_conf.get('type', 'SplunkSOAR')); soar_conf['verify_ssl'] = bool(soar_conf.get('verify_ssl', True)); soar_conf.setdefault('api_url', None); soar_conf.setdefault('auth_token', None); soar_conf.setdefault('auth_header_name', 'Authorization'); soar_conf.setdefault('auth_value_prefix', "")
        # Map View validation
        map_conf = self.app_config['map_view']; map_conf['image_path'] = str(map_conf.get('image_path')) if map_conf.get('image_path') else None;
        if not isinstance(map_conf.get('item_positions'), dict): map_conf['item_positions'] = {};
        valid_positions = {};
        for item_id, pos in map_conf['item_positions'].items():
            if isinstance(item_id, str) and isinstance(pos, dict) and 'x' in pos and 'y' in pos:
                try: valid_positions[item_id] = {'x': float(pos['x']), 'y': float(pos['y'])}
                except (ValueError, TypeError): pass
        map_conf['item_positions'] = valid_positions
        # Camera validation
        valid_cameras = []; unique_cam_raw_names = set(); unique_cam_sanitized_names = set()
        for i, cam_conf in enumerate(self.app_config['cameras']):
            if not isinstance(cam_conf, dict): continue; raw_name = str(cam_conf.get('name', '')).strip() or f"Camera_{i+1}_{int(time.time())}"
            if raw_name in unique_cam_raw_names: logger.error(f"Duplicate camera raw name '{raw_name}'. Skip."); continue; sanitized_name = sanitize_filename(raw_name)
            if sanitized_name in unique_cam_sanitized_names: logger.error(f"Duplicate sanitized name '{sanitized_name}'. Skip."); continue
            unique_cam_raw_names.add(raw_name); unique_cam_sanitized_names.add(sanitized_name); cam_conf['name'] = raw_name; cam_conf['onvif'] = bool(cam_conf.get('onvif', False)); cam_conf['url'] = str(cam_conf.get('url', '')) if cam_conf.get('url') is not None else None; cam_conf['host'] = str(cam_conf.get('host', '')) if cam_conf.get('host') is not None else None; try: port_val = cam_conf.get('port'); cam_conf['port'] = int(port_val) if port_val is not None else None; if cam_conf['port'] is not None and not (1 <= cam_conf['port'] <= 65535): cam_conf['port'] = None except (ValueError, TypeError): cam_conf['port'] = None; cam_conf['user'] = str(cam_conf.get('user', '')) if cam_conf.get('user') is not None else None; cam_conf['password'] = str(cam_conf.get('password', '')) if cam_conf.get('password') is not None else None; try: cam_conf['motion_threshold'] = max(0, int(cam_conf.get('motion_threshold', 500))) except (ValueError, TypeError): cam_conf['motion_threshold'] = 500; valid_cameras.append(cam_conf)
        self.app_config['cameras'] = valid_cameras
        # Sensor validation
        valid_sensors = []; unique_sensor_ids = set()
        for i, sensor_conf in enumerate(self.app_config['fence_sensors']):
            if not isinstance(sensor_conf, dict): continue; sensor_id = str(sensor_conf.get('id', '')).strip()
            if not sensor_id or not re.match(r'^[a-zA-Z0-9_-]+$', sensor_id): logger.error(f"Invalid sensor ID #{i+1}. Skip."); continue
            if sensor_id in unique_sensor_ids: logger.error(f"Duplicate sensor ID '{sensor_id}'. Skip #{i+1}."); continue
            unique_sensor_ids.add(sensor_id); sensor_conf['id'] = sensor_id; sensor_conf['name'] = str(sensor_conf.get('name', f"Sensor {sensor_id}")).strip() or f"Sensor {sensor_id}"; sensor_conf['type'] = str(sensor_conf.get('type', 'Other')); sensor_conf['severity'] = str(sensor_conf.get('severity', 'Medium')); if sensor_conf['severity'] not in ["Low", "Medium", "High", "Critical"]: sensor_conf['severity'] = "Medium"
            loc = sensor_conf.get('location'); if isinstance(loc, dict) and 'x' in loc and 'y' in loc: try: sensor_conf['location'] = {'x': float(loc['x']), 'y': float(loc['y'])} except (ValueError, TypeError): sensor_conf['location'] = {'x': 0.0, 'y': 0.0} else: sensor_conf['location'] = {'x': 0.0, 'y': 0.0}
            assoc_cams = sensor_conf.get('associated_cameras', []); if isinstance(assoc_cams, list): valid_assoc_cams = [str(name) for name in assoc_cams if isinstance(name, str) and name in unique_cam_sanitized_names]; if len(valid_assoc_cams) != len(assoc_cams): logger.warning(f"Sensor '{sensor_id}': Corrected associated_cameras."); sensor_conf['associated_cameras'] = valid_assoc_cams else: sensor_conf['associated_cameras'] = []
            valid_sensors.append(sensor_conf)
        self.app_config['fence_sensors'] = valid_sensors
        # Sensor Input validation
        sensor_input_conf = self.app_config['sensor_input']; sensor_input_conf['enabled'] = bool(sensor_input_conf.get('enabled', False)); sensor_input_conf['type'] = str(sensor_input_conf.get('type', 'logfile')); if sensor_input_conf['type'] not in ['logfile']: logger.warning(f"Unsupported sensor_input type '{sensor_input_conf['type']}'. Forcing 'logfile'."); sensor_input_conf['type'] = 'logfile'; sensor_input_conf.setdefault('path', 'sensor_alerts.log'); try: interval = int(sensor_input_conf.get('read_interval_ms', 2000)); sensor_input_conf['read_interval_ms'] = max(500, min(interval, 60000)) except (ValueError, TypeError): sensor_input_conf['read_interval_ms'] = 2000
        # Prune map positions
        active_item_ids = unique_cam_sanitized_names.union(unique_sensor_ids); current_map_keys = set(map_conf['item_positions'].keys()); stale_map_keys = current_map_keys - active_item_ids
        if stale_map_keys: logger.info(f"Pruning stale map positions: {stale_map_keys}");
            for key in stale_map_keys: map_conf['item_positions'].pop(key, None)
        logger.debug("Configuration validation complete.")

    def save_config(self, filepath: Optional[str] = None) -> bool:
        save_path = filepath or self.config_filepath; logger.info(f"Saving config to: {save_path}")
        if self.map_markers and 'map_view' in self.app_config:
             current_marker_positions = {}
             active_camera_sanitized_names = {sanitize_filename(cam.get('name','')) for cam in self.app_config.get('cameras', [])}
             active_sensor_ids = {sensor.get('id','') for sensor in self.app_config.get('fence_sensors', [])}
             active_item_ids = active_camera_sanitized_names.union(active_sensor_ids)
             for item_id, marker in self.map_markers.items():
                 if item_id in active_item_ids: pos = marker.pos(); current_marker_positions[item_id] = {'x': round(pos.x(), 2), 'y': round(pos.y(), 2)}
             self.app_config['map_view']['item_positions'] = current_marker_positions
        elif 'map_view' in self.app_config:
             if 'item_positions' not in self.app_config['map_view']: self.app_config['map_view']['item_positions'] = {}
        try:
            save_dir = os.path.dirname(save_path);
            if save_dir: os.makedirs(save_dir, exist_ok=True)
            with open(save_path, 'w', encoding='utf-8') as f: yaml.dump(self.app_config, f, default_flow_style=False, sort_keys=False, allow_unicode=True, indent=2)
            if platform.system() != "Windows":
                try: os.chmod(save_path, 0o600); logger.info(f"Set permissions for '{save_path}' to 600.")
                except Exception as e: logger.warning(f"Could not set permissions for '{save_path}': {e}.")
            logger.info(f"Configuration saved to {save_path}"); self._settings_dirty = False; self.update_window_title(); return True
        except Exception as e: logger.error(f"Error saving configuration to {save_path}: {e}", exc_info=True); self.notifications.show_message(f"Error saving config: {e}", level="error"); return False

    def mark_settings_dirty(self, dirty=True):
         if self._settings_dirty != dirty: self._settings_dirty = dirty; self.update_window_title()

    def update_window_title(self):
        base_title = "Security Monitor Pro (Versatile + Sensors)"; config_filename = os.path.basename(self.config_filepath) if self.config_filepath else "Untitled"; title = f"{base_title} - {config_filename}" + (" *" if self._settings_dirty else ""); self.setWindowTitle(title)

    def init_ui(self):
        logger.debug("Initializing UI..."); self.update_window_title()
        self.central_widget = QWidget(); self.setCentralWidget(self.central_widget); self.main_layout = QVBoxLayout(self.central_widget); self.main_layout.setContentsMargins(5, 5, 5, 5); self.main_layout.setSpacing(5)
        self.init_menu_bar(); self.status_bar = QStatusBar(); self.setStatusBar(self.status_bar); self.status_bar.showMessage("Initializing UI...")
        self.notifications = NotificationManager(self.central_widget); self.tabs = QTabWidget(); self.tabs.currentChanged.connect(self.on_tab_changed); self.main_layout.addWidget(self.tabs)
        self.create_monitor_tab(); self.create_map_view_tab(); self.create_settings_tab(); self.tabs.setCurrentIndex(0)
        self.status_bar.showMessage("UI Initialized.", 3000); logger.debug("UI Initialization complete.")

    def init_menu_bar(self):
        menu_bar = self.menuBar(); file_menu = menu_bar.addMenu("&File")
        load_action = QAction(QIcon.fromTheme("document-open", self._create_default_icon()), "Load Config...", self); load_action.setShortcut("Ctrl+O"); load_action.triggered.connect(self.load_config_dialog); file_menu.addAction(load_action)
        save_action = QAction(QIcon.fromTheme("document-save", self._create_default_icon()), "Save Config", self); save_action.setShortcut("Ctrl+S"); save_action.triggered.connect(lambda: self.save_config()); file_menu.addAction(save_action)
        save_as_action = QAction(QIcon.fromTheme("document-save-as", self._create_default_icon()), "Save Config As...", self); save_as_action.triggered.connect(self.save_config_dialog); file_menu.addAction(save_as_action)
        file_menu.addSeparator(); exit_action = QAction(QIcon.fromTheme("application-exit", self._create_default_icon()), "Exit", self); exit_action.setShortcut("Ctrl+Q"); exit_action.triggered.connect(self.close); file_menu.addAction(exit_action)
        help_menu = menu_bar.addMenu("&Help"); about_action = QAction(QIcon.fromTheme("help-about", self._create_default_icon()), "About", self); about_action.triggered.connect(self.show_about); help_menu.addAction(about_action)

    def on_tab_changed(self, index: int): logger.debug(f"Switched to tab index {index}: {self.tabs.tabText(index)}")

    def load_config_dialog(self):
         if self.check_unsaved_changes("load a new configuration file"):
             current_dir = os.path.dirname(self.config_filepath) if self.config_filepath else ""
             filepath, _ = QFileDialog.getOpenFileName(self, "Load Configuration", current_dir, "YAML Files (*.yaml *.yml);;All Files (*)")
             if filepath:
                 self.load_config(filepath); self.refresh_settings_ui(); self.stop_all_threads(); self.init_system(); self.recreate_monitor_tab(); self.load_map_image(); self.update_map_markers(); self.update_siem_timer_interval(); self.mark_settings_dirty(False); self.notifications.show_message(f"Config loaded from {os.path.basename(filepath)}.", level="success")

    def save_config_dialog(self):
         start_path = self.config_filepath or "config.yaml"; filepath, _ = QFileDialog.getSaveFileName(self, "Save Configuration As", start_path, "YAML Files (*.yaml *.yml);;All Files (*)")
         if filepath:
            if not (filepath.lower().endswith((".yaml", ".yml"))): filepath += ".yaml"
            if self.save_config(filepath): self.config_filepath = filepath; self.mark_settings_dirty(False); self.notifications.show_message(f"Config saved to {os.path.basename(filepath)}", level="success")

    def stop_all_threads(self):
        logger.info("Stopping all background threads..."); threads_to_stop = list(self.camera_threads.values());
        if self.sensor_monitor_thread and self.sensor_monitor_thread.isRunning(): threads_to_stop.append(self.sensor_monitor_thread)
        if not threads_to_stop: logger.info("No threads to stop."); return
        logger.info(f"Requesting stop for {len(threads_to_stop)} threads...");
        for thread in threads_to_stop:
            if thread and hasattr(thread, 'stop') and callable(thread.stop): try: thread.stop() except Exception as e: logger.error(f"Error stopping {getattr(thread,'objectName', type(thread).__name__)}: {e}")
        start_wait = time.time(); max_wait_sec = 10.0; threads_still_running = [t for t in threads_to_stop if t and t.isRunning()]; elapsed = 0
        while threads_still_running and elapsed < max_wait_sec: QApplication.processEvents(); time.sleep(0.1); elapsed = time.time() - start_wait; threads_still_running = [t for t in threads_still_running if t and t.isRunning()]
        if threads_still_running: logger.warning(f"{len(threads_still_running)} threads didn't stop gracefully: {[getattr(t,'objectName', type(t).__name__) for t in threads_still_running]}")
        else: logger.info("All background threads stopped gracefully.")
        # Clear state
        self.cameras.clear(); self.camera_threads.clear(); self.video_widgets.clear(); self.status_labels.clear(); self.motion_indicators.clear(); self.camera_group_boxes.clear(); self.ptz_control_widgets.clear(); self.sensor_monitor_thread = None;
        if self.map_scene:
             items_to_remove = list(self.map_markers.values())
             for item in items_to_remove:
                 if item in self.map_scene.items(): self.map_scene.removeItem(item)
                 try: item.markerClicked.disconnect(self.on_marker_clicked) except TypeError: pass
                 try: item.markerMoved.disconnect(self.on_marker_moved) except TypeError: pass
        self.map_markers.clear(); logger.info("Cleared runtime state dictionaries and map markers.")

    def init_system(self):
        logger.info("Initializing system components..."); self.status_bar.showMessage("Initializing system components...")
        QApplication.processEvents(); self.stop_all_threads()
        # Init Cameras
        camera_init_errors = []
        for config in self.app_config.get('cameras', []):
            raw_name = config.get('name', 'Unknown');
            try:
                camera = SecurityCamera(config); camera_key = camera.name;
                if camera_key in self.cameras: logger.error(f"Duplicate camera key '{camera_key}'. Skip."); camera_init_errors.append(f"{raw_name}: Key Collision"); continue
                self.cameras[camera_key] = camera; thread = CameraThread(camera, self); thread.new_frame.connect(self.update_video_frame, Qt.ConnectionType.QueuedConnection); thread.motion_detected_signal.connect(self.on_motion_detected, Qt.ConnectionType.QueuedConnection); thread.connection_status.connect(self.on_camera_connection_status, Qt.ConnectionType.QueuedConnection); self.camera_threads[camera_key] = thread; thread.start()
            except Exception as e: err_msg = f"Failed camera init '{raw_name}': {type(e).__name__}"; logger.error(err_msg + f"\n{traceback.format_exc()}"); camera_init_errors.append(f"{raw_name}: Init Error"); sanitized_name_key = sanitize_filename(raw_name); self.cameras.pop(sanitized_name_key, None); if sanitized_name_key in self.camera_threads: thread = self.camera_threads.pop(sanitized_name_key, None); thread.stop(); thread.wait(500)
        # Init SIEM
        self.siem_client = None; try:
            logger.debug("Initializing SIEM client..."); siem_config = self.app_config.get('siem', {}); self.siem_client = create_siem_client(siem_config)
            if self.siem_client: logger.info(f"SIEM client initialized ({siem_config.get('type')})."); QTimer.singleShot(1500, self.refresh_alerts)
            else:
                 if siem_config.get('enabled'): logger.warning("SIEM client init failed/disabled.")
                 else: logger.info("SIEM disabled in config.")
                 if hasattr(self, 'alerts_display'): self.alerts_display.setPlainText("SIEM client not configured/disabled.")
        except Exception as e: err_msg = f"SIEM init error: {e}"; logger.error(err_msg, exc_info=True); self.notifications.show_message(f"SIEM Init Error: {type(e).__name__}", level="error")
        # Init SOAR
        self.soar_client = None; try:
            logger.debug("Initializing SOAR client..."); soar_config = self.app_config.get('soar', {}); self.soar_client = create_soar_client(soar_config)
            if self.soar_client: logger.info(f"SOAR client initialized ({soar_config.get('type')}).");
                 if hasattr(self, 'soar_trigger_button'): self.soar_trigger_button.setEnabled(True)
            else:
                 if soar_config.get('enabled'): logger.warning("SOAR client init failed/disabled.")
                 else: logger.info("SOAR disabled in config.")
                 if hasattr(self, 'soar_trigger_button'): self.soar_trigger_button.setEnabled(False)
        except Exception as e: err_msg = f"SOAR init error: {e}"; logger.error(err_msg, exc_info=True); self.notifications.show_message(f"SOAR Init Error: {type(e).__name__}", level="error");
             if hasattr(self, 'soar_trigger_button'): self.soar_trigger_button.setEnabled(False)
        # Init Sensor Monitor
        self.sensor_definitions = self.app_config.get('fence_sensors', []); self.sensor_states.clear(); self.sensor_monitor_thread = None; sensor_input_config = self.app_config.get('sensor_input', {})
        if sensor_input_config.get('enabled', False):
            if sensor_input_config.get('type') == 'logfile':
                logger.info("Initializing Sensor Monitor Thread (logfile)...")
                try: self.sensor_monitor_thread = SensorMonitorThread(sensor_input_config, self.sensor_definitions, self); self.sensor_monitor_thread.sensor_alert.connect(self.on_sensor_alert, Qt.ConnectionType.QueuedConnection); self.sensor_monitor_thread.start()
                except Exception as e: logger.error(f"Failed to start SensorMonitorThread: {e}", exc_info=True); self.notifications.show_message(f"Sensor Monitor Error: {type(e).__name__}", level="error")
            else: logger.warning(f"Sensor input enabled but type '{sensor_input_config.get('type')}' unsupported.")
        else: logger.info("Sensor monitoring disabled in config.")
        # Update Map Markers
        self.update_map_markers()
        # Update Status Bar
        status_msg = "System ready."; num_cameras = len(self.cameras); num_sensors = len(self.sensor_definitions)
        if camera_init_errors: status_msg = f"{num_cameras} cam(s), {num_sensors} sensor(s) config. System init with {len(camera_init_errors)} cam error(s)."
        elif num_cameras == 0 and num_sensors == 0 : status_msg = "System ready. No cameras or sensors configured."
        else: status_msg = f"System ready. {num_cameras} camera(s), {num_sensors} sensor(s) configured."
        if self.sensor_monitor_thread is None and sensor_input_config.get('enabled', False): status_msg += " (Sensor monitor failed!)"
        self.status_bar.showMessage(status_msg, 5000); logger.info(f"System initialization finished. Status: {status_msg}")

    # --- SIEM/SOAR Alert Handling / Actions ---
    @pyqtSlot()
    def refresh_alerts(self):
        if not hasattr(self, 'alerts_display'): return
        if not self.siem_client: self.alerts_display.setPlainText("SIEM client not configured or disabled."); return
        logger.debug(f"Refreshing SIEM alerts..."); self.alerts_display.setPlainText("Fetching SIEM alerts..."); QApplication.processEvents()
        def fetch_task():
            try: alerts = self.siem_client.fetch_alerts(); QMetaObject.invokeMethod(self, "_update_alerts_display", Qt.ConnectionType.QueuedConnection, Q_ARG(list, alerts))
            except Exception as e: logger.error(f"SIEM fetch thread error: {e}", exc_info=True); QMetaObject.invokeMethod(self, "_update_alerts_display", Qt.ConnectionType.QueuedConnection, Q_ARG(list, [])); QMetaObject.invokeMethod(self.notifications, "show_message", Qt.ConnectionType.QueuedConnection, Q_ARG(str, f"SIEM Fetch Error: {type(e).__name__}"), Q_ARG(int, 5000), Q_ARG(str, "error"))
        import threading; fetch_thread = threading.Thread(target=fetch_task, name="SIEMFetchThread", daemon=True); fetch_thread.start()

    @pyqtSlot(list)
    def _update_alerts_display(self, alerts: List[Dict]):
        if not hasattr(self, 'alerts_display'): return
        logger.debug(f"Updating alerts display: {len(alerts)} alerts."); self.alerts_display.clear()
        if not alerts: self.alerts_display.setPlainText("No alerts found or error occurred."); return
        html_parts = [ "<style>p{margin-bottom:3px;line-height:1.3;}b{color:#aaddff;}hr{border:none;border-top:1px solid #555;margin:5px 0;}.raw{font-family:Consolas,'Courier New',monospace;white-space:pre-wrap;color:#ccc;font-size:8pt;display:block;background-color:#2f2f2f;padding:3px;border-radius:3px;}</style>" ]
        max_alerts_display = 150; alerts_to_display = alerts[:max_alerts_display]
        for alert in alerts_to_display:
            html_parts.append("<p>"); timestamp = alert.get('_time', ''); ts_display = escape(str(timestamp))
            if timestamp:
                try: parsed = False
                     if isinstance(timestamp, (int, float)): dt_obj = datetime.datetime.fromtimestamp(timestamp); ts_display = dt_obj.strftime('%Y-%m-%d %H:%M:%S'); parsed=True
                     else: ts_str = str(timestamp).strip().split('+')[0].replace('Z', '').split('.')[0];
                         for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%a %b %d %H:%M:%S %Y"]: try: dt_obj = datetime.datetime.strptime(ts_str, fmt); ts_display = dt_obj.strftime('%Y-%m-%d %H:%M:%S'); parsed = True; break; except ValueError: continue
                     if not parsed: ts_display = escape(str(timestamp))
                except Exception as time_e: logger.warning(f"Timestamp parse error '{timestamp}': {time_e}"); ts_display = escape(str(timestamp))
                html_parts.append(f"<b>Time:</b> {ts_display}<br>")
            host = escape(str(alert.get('host', 'N/A'))); source = escape(str(alert.get('source', 'N/A'))); sourcetype = escape(str(alert.get('sourcetype', 'N/A')))
            if host != 'N/A': html_parts.append(f"<b>Host:</b> {host}<br>")
            if sourcetype != 'N/A': html_parts.append(f"<b>Type:</b> {sourcetype}<br>")
            elif source != 'N/A': html_parts.append(f"<b>Source:</b> {source}<br>")
            raw_event = str(alert.get('_raw', 'No raw event.')); escaped_event = escape(raw_event); max_raw_len = 600; display_event = escaped_event[:max_raw_len] + ('...' if len(escaped_event) > max_raw_len else ''); html_parts.append(f"<span class='raw'>{display_event}</span></p><hr>")
        if len(alerts) > max_alerts_display: html_parts.append(f"<p><i>(Showing first {max_alerts_display} of {len(alerts)} alerts)</i></p>")
        self.alerts_display.setHtml("".join(html_parts)); self.alerts_display.moveCursor(QTextCursor.MoveOperation.Start); self.status_bar.showMessage(f"SIEM alerts refreshed: {len(alerts)} found.", 4000)

    def trigger_soar_action(self):
        if not self.soar_client: self.notifications.show_message("SOAR client not configured.", level="warning"); return
        soar_config = self.app_config.get('soar', {}); default_playbook_id = soar_config.get('default_playbook_id')
        if not default_playbook_id: QMessageBox.warning(self, "SOAR Action", "No default SOAR action configured."); logger.warning("Cannot trigger SOAR: No default playbook."); return
        action_name = "run_playbook"; parameters = { "playbook_id": default_playbook_id, "container_id": None, "name": f"Security Monitor Action {datetime.datetime.now().isoformat()}", "details": "Action triggered from Security Monitor.", }; logger.warning(f"Triggering SOAR '{action_name}': {parameters}"); self.notifications.show_message(f"Triggering SOAR '{action_name}'...", level="info"); QApplication.processEvents()
        def soar_task():
            try:
                result = self.soar_client.trigger_action(action_name, parameters); msg = result.get("message", "Unknown status."); level = "success" if result.get("success") else "error"; QMetaObject.invokeMethod(self.notifications, "show_message", Qt.ConnectionType.QueuedConnection, Q_ARG(str, f"SOAR Response: {msg}"), Q_ARG(int, 6000), Q_ARG(str, level))
            except NotImplementedError as nie: logger.error(f"SOAR action '{action_name}' not implemented."); QMetaObject.invokeMethod(self.notifications, "show_message", Qt.ConnectionType.QueuedConnection, Q_ARG(str, f"SOAR Action Not Implemented"), Q_ARG(int, 5000), Q_ARG(str, "error"))
            except Exception as e: logger.error(f"SOAR trigger thread error: {e}", exc_info=True); QMetaObject.invokeMethod(self.notifications, "show_message", Qt.ConnectionType.QueuedConnection, Q_ARG(str, f"SOAR Trigger Error: {type(e).__name__}"), Q_ARG(int, 5000), Q_ARG(str, "error"))
        import threading; soar_thread = threading.Thread(target=soar_task, name="SOARTriggerThread", daemon=True); soar_thread.start()

    # --- Monitor Tab UI ---
    def recreate_monitor_tab(self):
        logger.info("Recreating monitor tab...")
        monitor_tab_index = -1;
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i) == "Monitoring": monitor_tab_index = i; break
        if monitor_tab_index != -1:
            widget_to_remove = self.tabs.widget(monitor_tab_index)
            if widget_to_remove: current_tab_index = self.tabs.currentIndex(); self.tabs.removeTab(monitor_tab_index); widget_to_remove.deleteLater()
            else: logger.warning("Could not find widget for monitor tab.")
            self.video_widgets.clear(); self.status_labels.clear(); self.motion_indicators.clear(); self.camera_group_boxes.clear(); self.ptz_control_widgets.clear()
            self.create_monitor_tab()
            new_monitor_tab_index = 0 # Assumes it's always inserted at 0
            if current_tab_index == monitor_tab_index: self.tabs.setCurrentIndex(new_monitor_tab_index)
            elif 0 <= current_tab_index < monitor_tab_index : self.tabs.setCurrentIndex(current_tab_index)
            elif current_tab_index > monitor_tab_index: self.tabs.setCurrentIndex(current_tab_index - 1)
            else: self.tabs.setCurrentIndex(new_monitor_tab_index)
        else: logger.warning("Monitor tab not found, creating anew."); self.create_monitor_tab(); self.tabs.setCurrentIndex(0)

    def create_monitor_tab(self):
        monitor_tab = QWidget(); main_hbox = QHBoxLayout(monitor_tab); main_hbox.setContentsMargins(5, 5, 5, 5); main_hbox.setSpacing(10)
        # Camera Feeds Area
        camera_scroll_area = QScrollArea(); camera_scroll_area.setWidgetResizable(True); camera_scroll_area.setStyleSheet("QScrollArea { border: none; }")
        camera_area_container = QWidget(); camera_layout = QVBoxLayout(camera_area_container); camera_layout.setContentsMargins(0, 0, 0, 0); camera_layout.setSpacing(10)
        self.camera_group_boxes.clear(); self.video_widgets.clear(); self.status_labels.clear(); self.motion_indicators.clear(); self.ptz_control_widgets.clear()
        configured_cameras = self.app_config.get('cameras', [])
        if not configured_cameras: no_cam_label = QLabel("No cameras configured."); no_cam_label.setAlignment(Qt.AlignmentFlag.AlignCenter); no_cam_label.setStyleSheet("color: #aaa; margin: 20px;"); camera_layout.addWidget(no_cam_label, 0, Qt.AlignmentFlag.AlignCenter)
        else:
             logger.debug(f"Creating monitor widgets for {len(configured_cameras)} cameras...")
             for config in configured_cameras:
                 if camera_box := self._create_camera_widget(config): sanitized_name = sanitize_filename(config.get('name','Unknown')); self.camera_group_boxes[sanitized_name] = camera_box; camera_layout.addWidget(camera_box)
                 else: logger.error(f"Failed to create widget for camera: {config.get('name')}")
             camera_layout.addStretch()
        camera_scroll_area.setWidget(camera_area_container)
        # SIEM/SOAR Panel
        alerts_panel = QGroupBox("SIEM Alerts & SOAR Actions"); alerts_layout = QVBoxLayout(alerts_panel); alerts_layout.setContentsMargins(8, 8, 8, 8)
        if not hasattr(self, 'alerts_display'): self.alerts_display = QTextEdit(); self.alerts_display.setReadOnly(True); self.alerts_display.setStyleSheet("background-color:#262626;color:#ddd;border:1px solid #555;font-family:Consolas,'Courier New',monospace;font-size:9pt;"); self.alerts_display.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap); self.alerts_display.setPlainText("Initializing SIEM...")
        alerts_layout.addWidget(self.alerts_display, 1)
        button_hbox = QHBoxLayout(); button_hbox.setSpacing(10)
        self.refresh_btn = QPushButton(QIcon.fromTheme("view-refresh", self._create_default_icon("app")), " Refresh Alerts"); self.refresh_btn.setToolTip("Fetch latest SIEM alerts"); self.refresh_btn.clicked.connect(self.refresh_alerts); self.refresh_btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.soar_trigger_button = QPushButton(QIcon.fromTheme("system-run", self._create_default_icon("app")), " Trigger SOAR"); self.soar_trigger_button.setToolTip("Trigger a SOAR action"); self.soar_trigger_button.clicked.connect(self.trigger_soar_action); self.soar_trigger_button.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed); self.soar_trigger_button.setEnabled(bool(self.soar_client and self.soar_client.is_configured))
        button_hbox.addStretch(); button_hbox.addWidget(self.soar_trigger_button); button_hbox.addWidget(self.refresh_btn); alerts_layout.addLayout(button_hbox)
        # Add panels to main layout
        main_hbox.addWidget(camera_scroll_area, 65); main_hbox.addWidget(alerts_panel, 35)
        self.tabs.insertTab(0, monitor_tab, QIcon.fromTheme("video-display", self._create_default_icon("app")), "Monitoring"); logger.debug("Monitor tab created.")

    def _create_camera_widget(self, config: dict) -> Optional[QGroupBox]:
        camera_raw_name = config.get('name');
        if not camera_raw_name: logger.error("Missing 'name' for camera widget."); return None
        camera_sanitized_name = sanitize_filename(camera_raw_name); camera_box = QGroupBox(camera_raw_name); camera_box_layout = QVBoxLayout(camera_box); camera_box_layout.setContentsMargins(5, 8, 5, 5); camera_box_layout.setSpacing(4)
        top_hbox = QHBoxLayout(); top_hbox.setSpacing(8); video_label = QLabel("Initializing..."); video_label.setAlignment(Qt.AlignmentFlag.AlignCenter); video_label.setStyleSheet("background-color:#1e1e1e;color:#888;border:1px solid #444;border-radius:3px;"); video_label.setMinimumSize(320, 180); video_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding); self.video_widgets[camera_sanitized_name] = video_label; top_hbox.addWidget(video_label, 1)
        status_vbox = QVBoxLayout(); status_vbox.setSpacing(5); status_vbox.setAlignment(Qt.AlignmentFlag.AlignTop); status_label = QLabel("⚪ Waiting..."); status_label.setToolTip("Camera connection status"); status_label.setStyleSheet("font-size:8pt;color:#aaa;"); self.status_labels[camera_sanitized_name] = status_label; status_vbox.addWidget(status_label); motion_label = QLabel(); motion_label.setToolTip("Motion Detection Status"); motion_label.setFixedSize(16, 16); motion_label.setStyleSheet("background-color:transparent;border:1px solid #666;border-radius:8px;"); self.motion_indicators[camera_sanitized_name] = motion_label; status_vbox.addWidget(motion_label, 0, Qt.AlignmentFlag.AlignLeft); top_hbox.addLayout(status_vbox); camera_box_layout.addLayout(top_hbox, 1)
        controls_hbox = QHBoxLayout(); controls_hbox.setSpacing(5); controls_hbox.setContentsMargins(0, 5, 0, 0); snapshot_btn = QPushButton(QIcon.fromTheme("camera-photo", self._create_default_icon("app")), ""); snapshot_btn.setToolTip(f"Take Snapshot ({camera_raw_name})"); snapshot_btn.setFixedSize(30, 30); snapshot_btn.setIconSize(QSize(18, 18)); snapshot_btn.clicked.connect(lambda checked=False, name=camera_sanitized_name: self.take_snapshot(name)); controls_hbox.addWidget(snapshot_btn); controls_hbox.addSpacing(15)
        ptz_widget = QWidget(); ptz_layout = QHBoxLayout(ptz_widget); ptz_layout.setContentsMargins(0,0,0,0); ptz_layout.setSpacing(2); ptz_widget._ptz_buttons = []
        if config.get('onvif', False):
            ptz_buttons_map = self._create_ptz_controls(camera_sanitized_name); ptz_widget._ptz_buttons = list(ptz_buttons_map.values());
            for key in ["left", "up", "down", "right"]:
                if key in ptz_buttons_map: ptz_layout.addWidget(ptz_buttons_map[key])
            ptz_layout.addSpacing(10)
            for key in ["zoomin", "zoomout"]:
                if key in ptz_buttons_map: ptz_layout.addWidget(ptz_buttons_map[key])
            ptz_widget.setVisible(True)
        else: ptz_widget.setVisible(False)
        self.ptz_control_widgets[camera_sanitized_name] = ptz_widget; controls_hbox.addWidget(ptz_widget); controls_hbox.addStretch(); camera_box_layout.addLayout(controls_hbox)
        return camera_box

    def _create_ptz_controls(self, camera_sanitized_name: str) -> Dict[str, QPushButton]:
        buttons: Dict[str, QPushButton] = {}; ptz_button_size = QSize(28, 28); ptz_icon_size = QSize(16, 16); raw_name = camera_sanitized_name
        for cfg in self.app_config.get('cameras', []):
            if sanitize_filename(cfg.get('name','')) == camera_sanitized_name: raw_name = cfg.get('name'); break
        def create_ptz_button(key: str, icon_name: str, tooltip: str, pressed_action, released_action) -> QPushButton:
             icon = QIcon.fromTheme(icon_name, QIcon()); button = QPushButton(icon, ""); button.setToolTip(f"{tooltip} ({raw_name})"); button.setFixedSize(ptz_button_size); button.setIconSize(ptz_icon_size); button.setAutoRepeat(False); button.pressed.connect(pressed_action); button.released.connect(released_action); button.setEnabled(False); buttons[key] = button; return button
        ptz_speed = 0.6; zoom_speed = 0.5;
        create_ptz_button("up", "go-up", "Tilt Up", lambda name=camera_sanitized_name: self.start_ptz(name, 0, ptz_speed, 0), lambda name=camera_sanitized_name: self.stop_ptz(name))
        create_ptz_button("down", "go-down", "Tilt Down", lambda name=camera_sanitized_name: self.start_ptz(name, 0, -ptz_speed, 0), lambda name=camera_sanitized_name: self.stop_ptz(name))
        create_ptz_button("left", "go-previous", "Pan Left", lambda name=camera_sanitized_name: self.start_ptz(name, -ptz_speed, 0, 0), lambda name=camera_sanitized_name: self.stop_ptz(name))
        create_ptz_button("right", "go-next", "Pan Right", lambda name=camera_sanitized_name: self.start_ptz(name, ptz_speed, 0, 0), lambda name=camera_sanitized_name: self.stop_ptz(name))
        create_ptz_button("zoomin", "zoom-in", "Zoom In", lambda name=camera_sanitized_name: self.start_ptz(name, 0, 0, zoom_speed), lambda name=camera_sanitized_name: self.stop_ptz(name))
        create_ptz_button("zoomout", "zoom-out", "Zoom Out", lambda name=camera_sanitized_name: self.start_ptz(name, 0, 0, -zoom_speed), lambda name=camera_sanitized_name: self.stop_ptz(name))
        return buttons

    # --- UI Update Slots ---
    @pyqtSlot(str, object)
    def update_video_frame(self, camera_sanitized_name: str, frame: Any):
        video_label = self.video_widgets.get(camera_sanitized_name);
        if not video_label or not isinstance(frame, np.ndarray) or frame.size == 0: return
        try:
            h, w, ch = frame.shape;
            if ch != 3: return
            q_img = QImage(frame.data, w, h, ch * w, QImage.Format.Format_RGB888); pixmap = QPixmap.fromImage(q_img)
            if pixmap.isNull(): return
            label_size = video_label.size()
            if label_size.isValid() and label_size.width() > 10 and label_size.height() > 10:
                scaled_pixmap = pixmap.scaled(label_size, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation); video_label.setPixmap(scaled_pixmap)
                if video_label.text(): video_label.setText(""); video_label.setStyleSheet("background-color:#111;border:1px solid #444;border-radius:3px;")
        except Exception as e: logger.error(f"Error updating frame for {camera_sanitized_name}: {e}", exc_info=True);
             if video_label: video_label.setText(f"Frame Error\n{type(e).__name__}"); video_label.setStyleSheet("background-color:#300;color:red;border:1px solid red;")

    @pyqtSlot(str, bool, str)
    def on_camera_connection_status(self, camera_sanitized_name: str, is_connected: bool, error_message: str):
         logger.debug(f"Status '{camera_sanitized_name}': Connected={is_connected}, Err='{error_message[:50]}...'")
         status_label = self.status_labels.get(camera_sanitized_name); video_label = self.video_widgets.get(camera_sanitized_name); group_box = self.camera_group_boxes.get(camera_sanitized_name); ptz_widget = self.ptz_control_widgets.get(camera_sanitized_name)
         if not all([status_label, video_label, group_box]): return # ptz_widget can be None
         display_name = camera_sanitized_name;
         for cfg in self.app_config.get('cameras', []):
             if sanitize_filename(cfg.get('name','')) == camera_sanitized_name: display_name = cfg.get('name'); break
         if is_connected: status_label.setText("🟢 Connected"); status_label.setStyleSheet("font-size:8pt;color:#4CAF50;font-weight:bold;"); status_label.setToolTip("Connected."); group_box.setTitle(display_name);
             if video_label.text() and (not video_label.pixmap() or video_label.pixmap().isNull()): video_label.setText(""); video_label.setStyleSheet("background-color:#1e1e1e;color:#888;border:1px solid #444;border-radius:3px;")
         else: status_label.setText("🔴 Disconnected"); status_label.setStyleSheet("font-size:8pt;color:#F44336;font-weight:bold;"); tooltip = f"Disconnected.\n{error_message or 'No error info.'}".strip(); status_label.setToolTip(tooltip[:200]); group_box.setTitle(f"{display_name} (Offline)");
             current_pixmap = video_label.pixmap();
             if current_pixmap is None or current_pixmap.isNull(): display_error = error_message or "Connection failed."; video_label.setText(f"Disconnected\n({display_error[:100]}{'...' if len(display_error)>100 else ''})"); video_label.setStyleSheet("background-color:#333;color:#aaa;border:1px solid #555;border-radius:3px;"); video_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
         # Update PTZ buttons state
         camera_instance = self.cameras.get(camera_sanitized_name)
         if ptz_widget: # Check if PTZ widget exists for this camera
             can_ptz = False;
             if camera_instance and camera_instance.is_onvif: ptz_widget.setVisible(True); can_ptz = is_connected and camera_instance.ptz is not None; ptz_tooltip_suffix = ""
             else: ptz_widget.setVisible(False)
             if not is_connected: ptz_tooltip_suffix = " (Camera Offline)"
             elif camera_instance and camera_instance.ptz is None: ptz_tooltip_suffix = " (PTZ N/A)"
             ptz_buttons = getattr(ptz_widget, '_ptz_buttons', []);
             for button in ptz_buttons: button.setEnabled(can_ptz); base_tooltip = button.toolTip().split(' (')[0]; button.setToolTip(f"{base_tooltip} ({display_name}){ptz_tooltip_suffix}")

    @pyqtSlot(str)
    def on_motion_detected(self, camera_sanitized_name: str):
        indicator = self.motion_indicators.get(camera_sanitized_name); group_box = self.camera_group_boxes.get(camera_sanitized_name)
        if indicator: indicator.setStyleSheet("background-color:#ffdd00;border:1px solid #ffaa00;border-radius:8px;"); QTimer.singleShot(1200, lambda name=camera_sanitized_name: self._reset_motion_indicator(name))
        if group_box: self.highlight_widget(group_box, duration_ms=1500, color=QColor("#ffdd00"))

    def _reset_motion_indicator(self, camera_sanitized_name: str):
         indicator = self.motion_indicators.get(camera_sanitized_name);
         if indicator and "ffdd00" in indicator.styleSheet(): indicator.setStyleSheet("background-color:transparent;border:1px solid #666;border-radius:8px;")

    @pyqtSlot(dict)
    def on_sensor_alert(self, alert_data: dict):
        sensor_id = alert_data.get('id'); status = alert_data.get('status'); severity = alert_data.get('severity', 'Medium'); sensor_name = alert_data.get('name', sensor_id); timestamp = alert_data.get('timestamp', '')
        if not sensor_id: return
        logger.info(f"Sensor Alert: ID='{sensor_id}', Name='{sensor_name}', Status='{status}', Severity='{severity}'"); self.sensor_states[sensor_id] = alert_data
        marker = self.map_markers.get(sensor_id)
        if marker and isinstance(marker, MapMarkerItem):
            is_alerting = (status == 'triggered'); marker.setAlertState(is_alerting, severity)
            if is_alerting: pass # Future: Highlight marker itself
        if status == 'triggered':
             level = "warning";
             if severity == "High": level = "error"
             elif severity == "Critical": level = "error"
             self.notifications.show_message(f"ALERT: Sensor '{sensor_name}' triggered! (Severity: {severity})", level=level, duration=6000)
        elif status == 'normal': pass # Optional: Notify on clear?

    # --- Actions ---
    @pyqtSlot(str)
    def take_snapshot(self, camera_sanitized_name: str):
        logger.info(f"Snapshot requested: {camera_sanitized_name}"); video_label = self.video_widgets.get(camera_sanitized_name); pixmap = video_label.pixmap() if video_label else None
        if not pixmap or pixmap.isNull(): logger.warning(f"No image for {camera_sanitized_name}."); self.notifications.show_message(f"Cannot snapshot '{camera_sanitized_name}': No image.", level="warning"); return
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S"); default_filename = f"{camera_sanitized_name}_snapshot_{timestamp}.png"; snapshot_dir = "snapshots"
        try: os.makedirs(snapshot_dir, exist_ok=True)
        except OSError as e: logger.error(f"Snapshot dir error '{snapshot_dir}': {e}"); self.notifications.show_message(f"Snapshot Error: Cannot create dir.", level="error"); return
        default_path = os.path.join(snapshot_dir, default_filename); raw_name = camera_sanitized_name;
        for cfg in self.app_config.get('cameras', []):
             if sanitize_filename(cfg.get('name','')) == camera_sanitized_name: raw_name = cfg.get('name'); break
        file_path, selected_filter = QFileDialog.getSaveFileName(self, f"Save Snapshot - {raw_name}", default_path, "PNG (*.png);;JPEG (*.jpg *.jpeg);;BMP (*.bmp)")
        if file_path:
            abs_snapshot_dir = os.path.abspath(snapshot_dir); abs_file_path = os.path.abspath(file_path)
            if not abs_file_path.startswith(abs_snapshot_dir): logger.error(f"SECURITY: Snapshot path outside '{snapshot_dir}'. Abort."); self.notifications.show_message("Snapshot Error: Invalid save location.", level="error"); return
            try:
                img_format = None; ext = os.path.splitext(file_path)[1].lower()
                if selected_filter.startswith("PNG") or ext == ".png": img_format = "PNG"
                elif selected_filter.startswith("JPEG") or ext in [".jpg", ".jpeg"]: img_format = "JPG"
                elif selected_filter.startswith("BMP") or ext == ".bmp": img_format = "BMP"
                quality = 95 if img_format == "JPG" else -1
                if pixmap.save(file_path, format=img_format, quality=quality): logger.info(f"Snapshot saved: {file_path}"); self.notifications.show_message(f"Snapshot saved: {os.path.basename(file_path)}", level="success")
                else: logger.error(f"Failed save snapshot: {file_path}."); self.notifications.show_message("Failed to save snapshot.", level="error")
            except Exception as e: logger.error(f"Snapshot save exception: {e}", exc_info=True); self.notifications.show_message(f"Error saving snapshot: {e}", level="error")

    @pyqtSlot(str, float, float, float)
    def start_ptz(self, camera_sanitized_name: str, pan: float, tilt: float, zoom: float):
         logger.debug(f"PTZ Start: {camera_sanitized_name}, P={pan:.2f}, T={tilt:.2f}, Z={zoom:.2f}"); camera = self.cameras.get(camera_sanitized_name)
         if camera and camera.is_connected and camera.ptz: camera.move_ptz(pan, tilt, zoom)
         elif camera: logger.warning(f"PTZ Start ignored for {camera_sanitized_name}: Not connected/available.")
         else: logger.warning(f"PTZ Start ignored: Camera '{camera_sanitized_name}' not found.")

    @pyqtSlot(str)
    def stop_ptz(self, camera_sanitized_name: str):
        logger.debug(f"PTZ Stop: {camera_sanitized_name}"); camera = self.cameras.get(camera_sanitized_name)
        if camera and camera.is_connected and camera.ptz: camera.stop_ptz()
        elif camera: logger.debug(f"PTZ Stop ignored for {camera_sanitized_name}: Not connected/available.")
        else: logger.warning(f"PTZ Stop ignored: Camera '{camera_sanitized_name}' not found.")

    # ==================== Map View Tab Methods ====================
    def create_map_view_tab(self):
        map_tab = QWidget(); layout = QVBoxLayout(map_tab); layout.setContentsMargins(0,0,0,0); layout.setSpacing(0); toolbar = QToolBar("Map Tools"); toolbar.setIconSize(QSize(18, 18)); toolbar.setMovable(False); layout.addWidget(toolbar)
        load_map_action = QAction(QIcon.fromTheme("document-open", self._create_default_icon()), "Load Map...", self); load_map_action.triggered.connect(self.select_and_load_map_image); toolbar.addAction(load_map_action); toolbar.addSeparator()
        self.map_edit_mode_action = QAction(QIcon.fromTheme("document-edit", self._create_default_icon()), "Edit Layout", self); self.map_edit_mode_action.setCheckable(True); self.map_edit_mode_action.setChecked(self.map_edit_mode); self.map_edit_mode_action.triggered.connect(self.toggle_map_edit_mode); toolbar.addAction(self.map_edit_mode_action); toolbar.addSeparator()
        zoom_in = QAction(QIcon.fromTheme("zoom-in", self._create_default_icon()), "Zoom In", self); zoom_in.triggered.connect(lambda: self.map_view.scale(1.2, 1.2) if self.map_view else None); zoom_in.setShortcut("Ctrl++"); toolbar.addAction(zoom_in)
        zoom_out = QAction(QIcon.fromTheme("zoom-out", self._create_default_icon()), "Zoom Out", self); zoom_out.triggered.connect(lambda: self.map_view.scale(1/1.2, 1/1.2) if self.map_view else None); zoom_out.setShortcut("Ctrl+-"); toolbar.addAction(zoom_out)
        zoom_fit = QAction(QIcon.fromTheme("zoom-fit-best", self._create_default_icon()), "Fit View", self); zoom_fit.triggered.connect(self.fit_map_to_view); zoom_fit.setShortcut("Ctrl+0"); toolbar.addAction(zoom_fit); toolbar.addSeparator()
        pan_mode = QAction(QIcon.fromTheme("transform-move", self._create_default_icon()), "Pan Mode", self); pan_mode.setCheckable(True); pan_mode.setChecked(True); pan_mode.triggered.connect(lambda: self.map_view.setDragMode(QGraphicsView.DragMode.ScrollHandDrag) if self.map_view else None); mode_group = QActionGroup(self); mode_group.addAction(pan_mode); mode_group.setExclusive(True); toolbar.addAction(pan_mode)
        self.map_scene = QGraphicsScene(self); self.map_view = QGraphicsView(self.map_scene); self.map_view.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.SmoothPixmapTransform); self.map_view.setDragMode(QGraphicsView.DragMode.ScrollHandDrag); self.map_view.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse); self.map_view.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        view_bg = self.palette().color(QPalette.ColorRole.AlternateBase); self.map_view.setBackgroundBrush(view_bg); scene_bg = self.palette().color(QPalette.ColorRole.Base); self.map_scene.setBackgroundBrush(scene_bg); self.map_view.setStyleSheet("QGraphicsView { border: 1px solid #444; }"); layout.addWidget(self.map_view)
        self.load_map_image(); self.tabs.insertTab(1, map_tab, QIcon.fromTheme("applications-geomap", self._create_default_icon("app")), "Map View"); logger.debug("Map View tab created.")

    def select_and_load_map_image(self):
        current_path = self.app_config['map_view'].get('image_path'); start_dir = os.path.dirname(current_path) if current_path and os.path.exists(os.path.dirname(current_path)) else ""
        filepath, _ = QFileDialog.getOpenFileName(self, "Load Map Background", start_dir, "Images (*.png *.jpg *.jpeg *.bmp *.gif);;All Files (*)")
        if filepath and self.app_config['map_view'].get('image_path') != filepath:
             logger.info(f"New map image selected: {filepath}"); self.app_config['map_view']['image_path'] = filepath; self.load_map_image(); self.mark_settings_dirty()
             reply = QMessageBox.question(self, "Save Config?", f"Map image changed.\nSave config?", QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Save)
             if reply == QMessageBox.StandardButton.Save: self.save_config()

    def load_map_image(self):
        if not self.map_scene or not self.map_view: return
        map_path = self.app_config['map_view'].get('image_path'); logger.debug(f"Loading map image: {map_path}")
        if self.map_background_item and self.map_background_item in self.map_scene.items(): self.map_scene.removeItem(self.map_background_item); self.map_background_item = None; logger.debug("Removed existing map BG."); self.map_scene.setSceneRect(QRectF())
        if map_path and os.path.exists(map_path):
            try:
                pixmap = QPixmap(map_path);
                if pixmap.isNull(): raise ValueError("Loaded pixmap is null.")
                self.map_background_item = QGraphicsPixmapItem(pixmap); self.map_background_item.setZValue(-10); self.map_scene.addItem(self.map_background_item)
                self.map_scene.setSceneRect(self.map_background_item.boundingRect()); self.fit_map_to_view(); logger.info(f"Loaded map image: {map_path}"); self.status_bar.showMessage(f"Map loaded: {os.path.basename(map_path)}", 5000)
            except Exception as e: logger.error(f"Failed to load map '{map_path}': {e}", exc_info=True); self.notifications.show_message(f"Error loading map: {os.path.basename(map_path)} - {type(e).__name__}", level="error");
                if self.map_scene.sceneRect().isEmpty(): self.map_scene.setSceneRect(QRectF(0,0,800,600)); self.fit_map_to_view()
        else:
            if map_path: logger.warning(f"Map image not found: {map_path}"); self.notifications.show_message(f"Map image not found: {os.path.basename(map_path)}", level="warning")
            else: logger.info("No map image configured."); self.status_bar.showMessage("No map image loaded.", 5000)
            if self.map_scene.sceneRect().isEmpty() and not self.map_scene.items(): self.map_scene.setSceneRect(QRectF(0,0,800,600)); self.fit_map_to_view()

    def fit_map_to_view(self):
        if not self.map_view or not self.map_scene: return
        rect_to_fit = self.map_scene.itemsBoundingRect();
        if not rect_to_fit.isValid() or rect_to_fit.isEmpty(): rect_to_fit = self.map_scene.sceneRect()
        if rect_to_fit.isValid() and not rect_to_fit.isEmpty() and rect_to_fit.width() > 0 and rect_to_fit.height() > 0:
             margin = max(10, rect_to_fit.width() * 0.05); rect_with_margin = rect_to_fit.adjusted(-margin, -margin, margin, margin); self.map_view.fitInView(rect_with_margin, Qt.AspectRatioMode.KeepAspectRatio)
        else: logger.debug("fit_map_to_view skipped: Scene/items rect empty.")

    def update_map_markers(self):
        if not self.map_scene: return; logger.debug("Updating map markers...")
        current_cameras = self.app_config.get('cameras', []); current_sensors = self.app_config.get('fence_sensors', []); item_positions = self.app_config['map_view'].get('item_positions', {})
        active_camera_sanitized_names = {sanitize_filename(cam.get('name','')) for cam in current_cameras}; active_sensor_ids = {sensor.get('id','') for sensor in current_sensors}; active_item_ids = active_camera_sanitized_names.union(active_sensor_ids); existing_marker_ids = set(self.map_markers.keys()); ids_to_remove = existing_marker_ids - active_item_ids
        for item_id in ids_to_remove:
            marker = self.map_markers.pop(item_id, None);
            if marker and marker in self.map_scene.items(): self.map_scene.removeItem(marker); try: marker.markerClicked.disconnect(self.on_marker_clicked) except TypeError: pass; try: marker.markerMoved.disconnect(self.on_marker_moved) except TypeError: pass; logger.debug(f"Removed stale marker: {item_id}")
            elif marker: logger.warning(f"Stale marker '{item_id}' in dict but not scene.")
        # Update/Create Camera Markers
        if self._default_camera_icon:
            for config in current_cameras:
                raw_name = config.get('name'); sanitized_name = sanitize_filename(raw_name); if not sanitized_name: continue
                marker = self.map_markers.get(sanitized_name); pos_data = item_positions.get(sanitized_name); position = QPointF(float(pos_data['x']), float(pos_data['y'])) if isinstance(pos_data, dict) else None
                if marker:
                    if position and marker.pos() != position: logger.debug(f"Update cam pos '{sanitized_name}' to {position}"); marker.setPos(position)
                    marker.setEditMode(self.map_edit_mode);
                    if marker not in self.map_scene.items(): self.map_scene.addItem(marker)
                elif position:
                    try: logger.debug(f"Create cam marker '{sanitized_name}' at {position}"); marker = MapMarkerItem(sanitized_name, 'camera', self._default_camera_icon.copy(), position, self); marker.setEditMode(self.map_edit_mode); marker.markerClicked.connect(self.on_marker_clicked); marker.markerMoved.connect(self.on_marker_moved); self.map_scene.addItem(marker); self.map_markers[sanitized_name] = marker
                    except Exception as e: logger.error(f"Failed create cam marker {sanitized_name}: {e}", exc_info=True)
        else: logger.error("Cannot update cam markers: Icon missing.")
        # Update/Create Sensor Markers
        default_sensor_icon = self.sensor_icons.get('sensor_normal')
        if default_sensor_icon:
            for config in current_sensors:
                sensor_id = config.get('id'); if not sensor_id: continue
                marker = self.map_markers.get(sensor_id); pos_data = item_positions.get(sensor_id); position = QPointF(float(pos_data['x']), float(pos_data['y'])) if isinstance(pos_data, dict) else None
                current_state = self.sensor_states.get(sensor_id, {}); is_alerting = (current_state.get('status') == 'triggered'); severity = current_state.get('severity', config.get('severity', 'Medium'))
                if marker:
                    if position and marker.pos() != position: logger.debug(f"Update sensor pos '{sensor_id}' to {position}"); marker.setPos(position)
                    marker.setEditMode(self.map_edit_mode); marker.setAlertState(is_alerting, severity);
                    if marker not in self.map_scene.items(): self.map_scene.addItem(marker)
                elif position:
                    try: logger.debug(f"Create sensor marker '{sensor_id}' at {position}"); marker = MapMarkerItem(sensor_id, 'sensor', default_sensor_icon.copy(), position, self); marker.setEditMode(self.map_edit_mode); marker.setAlertState(is_alerting, severity); marker.markerClicked.connect(self.on_marker_clicked); marker.markerMoved.connect(self.on_marker_moved); self.map_scene.addItem(marker); self.map_markers[sensor_id] = marker
                    except Exception as e: logger.error(f"Failed create sensor marker {sensor_id}: {e}", exc_info=True)
        else: logger.error("Cannot update sensor markers: Icon missing.")
        logger.debug(f"Map markers update complete. Count: {len(self.map_markers)}")

    @pyqtSlot(bool)
    def toggle_map_edit_mode(self, checked: bool):
        if self.map_edit_mode == checked: return
        if not checked and self._settings_dirty:
             reply = QMessageBox.question(self, "Save Map Layout?", "Unsaved item positions.\nSave config?", QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Save)
             if reply == QMessageBox.StandardButton.Save:
                 if not self.save_config(): self.map_edit_mode_action.setChecked(True); return
             elif reply == QMessageBox.StandardButton.Discard: logger.info("Discarding map changes by reloading."); current_filepath = self.config_filepath; self.load_config(current_filepath); self.update_map_markers(); self.refresh_settings_ui(); self.mark_settings_dirty(False)
             elif reply == QMessageBox.StandardButton.Cancel: self.map_edit_mode_action.setChecked(True); logger.info("Exit Map Edit Mode cancelled."); return
        self.map_edit_mode = checked; logger.info(f"Map Edit Mode: {'ON' if checked else 'OFF'}"); self.status_bar.showMessage(f"Map Edit Mode: {'ENABLED' if checked else 'DISABLED'}", 3000)
        for marker in self.map_markers.values(): marker.setEditMode(self.map_edit_mode)
        if checked: self._add_markers_for_unplaced_items()

    def _add_markers_for_unplaced_items(self):
        logger.debug("Checking for unplaced items..."); if not self.map_scene: return
        current_cameras = self.app_config.get('cameras', []); current_sensors = self.app_config.get('fence_sensors', []); active_camera_sanitized_names = {sanitize_filename(cam.get('name','')) for cam in current_cameras}; active_sensor_ids = {sensor.get('id','') for sensor in current_sensors}; placed_item_ids = set(self.map_markers.keys())
        unplaced_cameras = active_camera_sanitized_names - placed_item_ids; unplaced_sensors = active_sensor_ids - placed_item_ids
        if not unplaced_cameras and not unplaced_sensors: logger.debug("No unplaced items."); return
        logger.info(f"Found {len(unplaced_cameras)} unplaced cameras, {len(unplaced_sensors)} unplaced sensors."); scene_rect = self.map_scene.sceneRect(); center_pos = scene_rect.center() if scene_rect.isValid() else QPointF(50,50); num_unplaced = len(unplaced_cameras) + len(unplaced_sensors); radius = 40 + (num_unplaced * 3); angle_step = 360.0 / max(1, num_unplaced); current_angle_idx = 0
        if self._default_camera_icon:
            for i, cam_sanitized_name in enumerate(unplaced_cameras):
                angle = current_angle_idx * angle_step * (np.pi / 180.0); initial_pos = center_pos + QPointF(radius * np.cos(angle), radius * np.sin(angle)); current_angle_idx += 1; logger.debug(f"Placing temp cam marker '{cam_sanitized_name}' near {initial_pos}")
                try: marker = MapMarkerItem(cam_sanitized_name, 'camera', self._default_camera_icon.copy(), initial_pos, self); marker.setEditMode(True); marker.markerClicked.connect(self.on_marker_clicked); marker.markerMoved.connect(self.on_marker_moved); self.map_scene.addItem(marker); self.map_markers[cam_sanitized_name] = marker; self.on_marker_moved(cam_sanitized_name, marker.pos())
                except Exception as e: logger.error(f"Failed create initial cam marker '{cam_sanitized_name}': {e}", exc_info=True)
        else: logger.error("Cannot add unplaced cam markers: Icon missing.")
        default_sensor_icon = self.sensor_icons.get('sensor_normal')
        if default_sensor_icon:
            for i, sensor_id in enumerate(unplaced_sensors):
                angle = current_angle_idx * angle_step * (np.pi / 180.0); initial_pos = center_pos + QPointF(radius * np.cos(angle), radius * np.sin(angle)); current_angle_idx += 1; logger.debug(f"Placing temp sensor marker '{sensor_id}' near {initial_pos}")
                try: marker = MapMarkerItem(sensor_id, 'sensor', default_sensor_icon.copy(), initial_pos, self); marker.setEditMode(True); marker.markerClicked.connect(self.on_marker_clicked); marker.markerMoved.connect(self.on_marker_moved); self.map_scene.addItem(marker); self.map_markers[sensor_id] = marker; self.on_marker_moved(sensor_id, marker.pos())
                except Exception as e: logger.error(f"Failed create initial sensor marker '{sensor_id}': {e}", exc_info=True)
        else: logger.error("Cannot add unplaced sensor markers: Icon missing.")
        if unplaced_cameras or unplaced_sensors: self.mark_settings_dirty()

    @pyqtSlot(str, QPointF)
    def on_marker_moved(self, item_id: str, new_pos: QPointF):
         marker = self.map_markers.get(item_id)
         if not marker: logger.warning(f"markerMoved signal for unknown ID: {item_id}"); return
         if 'map_view' not in self.app_config: self.app_config['map_view'] = {}
         if 'item_positions' not in self.app_config['map_view']: self.app_config['map_view']['item_positions'] = {}
         rounded_pos = {'x': round(new_pos.x(), 2), 'y': round(new_pos.y(), 2)}
         config_updated = False
         # Always store position under item_positions now
         if self.app_config['map_view']['item_positions'].get(item_id) != rounded_pos:
             self.app_config['map_view']['item_positions'][item_id] = rounded_pos
             logger.info(f"Updated map position for '{item_id}' ({marker.item_type}) in map_view config.")
             config_updated = True
         # ALSO update the sensor definition's location field if it's a sensor
         if marker.item_type == 'sensor':
              sensor_updated = False
              for sensor_conf in self.app_config.get('fence_sensors', []):
                  if sensor_conf.get('id') == item_id:
                      if sensor_conf.get('location') != rounded_pos:
                           sensor_conf['location'] = rounded_pos
                           logger.info(f"Updated location field for sensor '{item_id}' in fence_sensors config.")
                           sensor_updated = True; config_updated = True
                      break
              if not sensor_updated: logger.warning(f"Moved sensor '{item_id}' but couldn't find its definition.")
         if config_updated: self.mark_settings_dirty()

    @pyqtSlot(str)
    def on_marker_clicked(self, item_id: str):
        if self.map_edit_mode: logger.debug(f"Marker click '{item_id}': Edit Mode ON."); return
        marker = self.map_markers.get(item_id)
        if not marker: logger.warning(f"Marker clicked, ID '{item_id}' not found."); return
        monitor_tab_index = -1;
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i) == "Monitoring": monitor_tab_index = i; break
        if monitor_tab_index == -1: logger.warning("Monitor tab not found."); return
        self.tabs.setCurrentIndex(monitor_tab_index); QApplication.processEvents()
        if marker.item_type == 'camera':
            logger.info(f"Cam marker clicked: '{item_id}'. Highlight view."); group_box = self.camera_group_boxes.get(item_id)
            if group_box: monitor_tab_widget = self.tabs.widget(monitor_tab_index); scroll_area = monitor_tab_widget.findChild(QScrollArea);
                 if scroll_area: scroll_area.ensureWidgetVisible(group_box, yMargin=50); QApplication.processEvents()
                 self.highlight_widget(group_box, duration_ms=1200, color=QColor(42, 130, 218))
            else: logger.warning(f"GroupBox for camera '{item_id}' not found.")
        elif marker.item_type == 'sensor':
            logger.info(f"Sensor marker clicked: '{item_id}'. Highlight associated cams.")
            sensor_config = next((conf for conf in self.app_config.get('fence_sensors', []) if conf.get('id') == item_id), None)
            if not sensor_config: logger.warning(f"Sensor config for ID '{item_id}' not found."); return
            associated_camera_sanitized_names = sensor_config.get('associated_cameras', [])
            if not associated_camera_sanitized_names: self.notifications.show_message(f"Sensor '{sensor_config.get('name', item_id)}' has no associated cameras.", level="info"); return
            logger.debug(f"Sensor '{item_id}' associated cams: {associated_camera_sanitized_names}"); monitor_tab_widget = self.tabs.widget(monitor_tab_index); scroll_area = monitor_tab_widget.findChild(QScrollArea); first_widget_to_scroll = None
            for cam_name in associated_camera_sanitized_names:
                group_box = self.camera_group_boxes.get(cam_name)
                if group_box:
                    if not first_widget_to_scroll: first_widget_to_scroll = group_box
                    self.highlight_widget(group_box, duration_ms=1500, color=QColor(255, 165, 0))
                else: logger.warning(f"Associated camera GroupBox '{cam_name}' not found (for sensor '{item_id}').")
            if first_widget_to_scroll and scroll_area: scroll_area.ensureWidgetVisible(first_widget_to_scroll, yMargin=50); QApplication.processEvents()
            elif not scroll_area: logger.warning(f"ScrollArea not found on monitor tab.")
        else: logger.warning(f"Unknown marker type clicked: '{marker.item_type}'")

    def highlight_widget(self, widget: Union[QWidget, QGraphicsItem], duration_ms: int = 1500, color: QColor = QColor(Qt.GlobalColor.yellow)):
        if not widget: return
        if isinstance(widget, QWidget): # Handle QGroupBox etc.
            anim_prop_name = b"_highlight_anim_color"; original_stylesheet = widget.styleSheet()
            if existing_anim := widget.property(anim_prop_name):
                 if isinstance(existing_anim, QVariantAnimation): existing_anim.stop(); widget.setStyleSheet(original_stylesheet)
            start_color = color; base_border_color = QColor("#666666")
            try: style_parts = original_stylesheet.split('border:');
                 if len(style_parts) > 1: border_part = style_parts[1].split(';')[0].strip(); color_part = border_part.split()[-1]; temp_color = QColor(color_part);
                      if temp_color.isValid(): base_border_color = temp_color
            except Exception: pass
            animation = QVariantAnimation(widget); widget.setProperty(anim_prop_name, animation); animation.setDuration(duration_ms); animation.setStartValue(start_color); animation.setEndValue(base_border_color); animation.setEasingCurve(QEasingCurve.Type.InOutCubic)
            def update_border_color(current_color: QColor):
                try: style_prefix = ""; style_suffix = ""; border_width = "1px"; radius = "6px"; margin = "0.6em"; padding = "0.8em 0.5em 0.5em 0.5em"
                     if isinstance(widget, QGroupBox): style_prefix = "QGroupBox { ";
                          if 'font-weight: bold;' in original_stylesheet: style_prefix += "font-weight: bold; "; style_suffix = f" border-radius: {radius}; margin-top: {margin}; padding: {padding}; }}"
                     if 'border:' in original_stylesheet: parts = original_stylesheet.split('border:')[1].split(';')[0].split();
                          if len(parts) > 1 and 'px' in parts[0]: border_width = parts[0]
                     border_color_str = current_color.name(QColor.NameFormat.HexRgb); new_style = f"{style_prefix} border: {border_width} solid {border_color_str}; {style_suffix}"; widget.setStyleSheet(new_style)
                except Exception as e: logger.error(f"Error setting highlight style: {e}");
                     if animation and animation.state() == QVariantAnimation.State.Running: animation.stop()
            animation.valueChanged.connect(update_border_color); animation.finished.connect(lambda w=widget, style=original_stylesheet, prop_name=anim_prop_name: self._on_highlight_finished(w, style, prop_name)); animation.start(QVariantAnimation.DeletionPolicy.DeleteWhenStopped)
        elif isinstance(widget, QGraphicsItem):
             # Highlighting QGraphicsItem is different - use effects or redraw
             logger.debug(f"Highlight requested for QGraphicsItem '{getattr(widget,'item_id','?')}' - not fully implemented.")
             # Example: Use opacity animation for a simple blink effect
             # effect = QGraphicsOpacityEffect(widget); widget.setGraphicsEffect(effect)
             # anim = QPropertyAnimation(effect, b"opacity"); anim.setDuration(duration_ms // 2); anim.setLoopCount(2) # Blink once
             # anim.setKeyValueAt(0, 1.0); anim.setKeyValueAt(0.5, 0.3); anim.setKeyValueAt(1, 1.0)
             # anim.finished.connect(lambda: widget.setGraphicsEffect(None)) # Remove effect when done
             # anim.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)

    def _on_highlight_finished(self, widget: Optional[QWidget], original_stylesheet: str, prop_name: bytes):
         if widget: widget.setStyleSheet(original_stylesheet); widget.setProperty(prop_name, None)


    # ==================== Settings Tab Methods ====================
    def create_settings_tab(self):
        settings_tab = QWidget(); scroll_area = QScrollArea(); scroll_area.setWidgetResizable(True); scroll_area.setStyleSheet("QScrollArea { border: none; background-color: transparent; }"); scroll_content = QWidget(); scroll_area.setWidget(scroll_content); layout = QVBoxLayout(scroll_content); layout.setSpacing(15); layout.setContentsMargins(10, 10, 10, 20)
        # --- MFA Section ---
        mfa_group = QGroupBox("Application Security (MFA/2FA)"); mfa_layout = QVBoxLayout(mfa_group); mfa_layout.setSpacing(10); self.mfa_status_label = QLabel("Checking..."); self.mfa_status_label.setWordWrap(True); mfa_layout.addWidget(self.mfa_status_label); self.manage_mfa_button = QPushButton("Setup / Manage 2FA..."); self.manage_mfa_button.clicked.connect(self.open_mfa_dialog); mfa_layout.addWidget(self.manage_mfa_button, 0, Qt.AlignmentFlag.AlignLeft); layout.addWidget(mfa_group); self.update_mfa_status_label()
        # --- Camera Section ---
        cam_group = QGroupBox("Camera Configuration"); cam_layout = QHBoxLayout(cam_group); cam_layout.setSpacing(10); self.camera_list_widget = QListWidget(); self.camera_list_widget.setToolTip("Double-click to edit."); self.camera_list_widget.itemDoubleClicked.connect(self.edit_camera_config); self.camera_list_widget.setAlternatingRowColors(True); cam_layout.addWidget(self.camera_list_widget, 1); cam_buttons_layout = QVBoxLayout(); cam_buttons_layout.setSpacing(8); add_cam_btn = QPushButton(QIcon.fromTheme("list-add", self._create_default_icon()), " Add Camera..."); add_cam_btn.clicked.connect(self.add_camera_config); cam_buttons_layout.addWidget(add_cam_btn); edit_cam_btn = QPushButton(QIcon.fromTheme("document-edit", self._create_default_icon()), " Edit Selected..."); edit_cam_btn.clicked.connect(self.edit_camera_config); cam_buttons_layout.addWidget(edit_cam_btn); remove_cam_btn = QPushButton(QIcon.fromTheme("list-remove", self._create_default_icon()), " Remove Selected"); remove_cam_btn.clicked.connect(self.remove_camera_config); cam_buttons_layout.addWidget(remove_cam_btn); cam_buttons_layout.addStretch(); cam_layout.addLayout(cam_buttons_layout); layout.addWidget(cam_group)
        # --- Sensor Section ---
        sensor_group = QGroupBox("Fence Sensor Configuration"); sensor_layout = QHBoxLayout(sensor_group); sensor_layout.setSpacing(10); self.sensor_list_widget = QListWidget(); self.sensor_list_widget.setToolTip("Double-click to edit."); self.sensor_list_widget.itemDoubleClicked.connect(self.edit_sensor_config); self.sensor_list_widget.setAlternatingRowColors(True); sensor_layout.addWidget(self.sensor_list_widget, 1); sensor_buttons_layout = QVBoxLayout(); sensor_buttons_layout.setSpacing(8); add_sensor_btn = QPushButton(QIcon.fromTheme("list-add"), " Add Sensor..."); add_sensor_btn.clicked.connect(self.add_sensor_config); sensor_buttons_layout.addWidget(add_sensor_btn); edit_sensor_btn = QPushButton(QIcon.fromTheme("document-edit"), " Edit Selected..."); edit_sensor_btn.clicked.connect(self.edit_sensor_config); sensor_buttons_layout.addWidget(edit_sensor_btn); remove_sensor_btn = QPushButton(QIcon.fromTheme("list-remove"), " Remove Selected"); remove_sensor_btn.clicked.connect(self.remove_sensor_config); sensor_buttons_layout.addWidget(remove_sensor_btn); sensor_buttons_layout.addStretch(); sensor_layout.addLayout(sensor_buttons_layout); layout.addWidget(sensor_group)
        # --- Sensor Input Section ---
        sensor_input_group = QGroupBox("Sensor Input Configuration"); sensor_input_layout = QFormLayout(sensor_input_group); sensor_input_layout.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows); sensor_input_layout.setSpacing(10); self.sensor_input_enabled_check = QCheckBox("Enable Sensor Monitoring"); self.sensor_input_type_combo = QComboBox(); self.sensor_input_type_combo.addItems(["logfile"]); self.sensor_input_type_combo.setEnabled(False); self.sensor_input_path_input = QLineEdit(); self.sensor_input_path_input.setPlaceholderText("e.g., sensor_alerts.log"); self.sensor_input_interval_input = QSpinBox(); self.sensor_input_interval_input.setRange(500, 60000); self.sensor_input_interval_input.setSuffix(" ms"); self.sensor_input_interval_input.setToolTip("Check interval (500ms - 60s)")
        sensor_input_layout.addRow(self.sensor_input_enabled_check); sensor_input_layout.addRow("Input Type:", self.sensor_input_type_combo); sensor_input_layout.addRow("Log File Path:", self.sensor_input_path_input); sensor_input_layout.addRow("Read Interval:", self.sensor_input_interval_input); layout.addWidget(sensor_input_group)
        # --- SIEM Section ---
        siem_group = QGroupBox("SIEM Integration"); siem_layout = QFormLayout(siem_group); siem_layout.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow); siem_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight); siem_layout.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows); siem_layout.setSpacing(10); self.siem_enabled_check = QCheckBox("Enable SIEM"); siem_layout.addRow(self.siem_enabled_check); self.siem_type_combo = QComboBox(); self.siem_type_combo.addItems(list(SIEM_TYPE_MAP.keys())); siem_layout.addRow("SIEM Type:", self.siem_type_combo); self.siem_url_input = QLineEdit(); self.siem_auth_token_input = QLineEdit(); self.siem_auth_token_input.setEchoMode(QLineEdit.EchoMode.Password); self.siem_username_input = QLineEdit(); self.siem_verify_ssl_check = QCheckBox("Verify SSL"); self.siem_refresh_input = QLineEdit(); env_tooltip_siem = "Use 'ENV:VAR_NAME' for environment variable."; self.siem_url_input.setToolTip(f"API URL.\n{env_tooltip_siem}"); self.siem_auth_token_input.setToolTip(f"Token/Key/Pass.\n{env_tooltip_siem}"); self.siem_username_input.setToolTip(f"Basic Auth User.\n{env_tooltip_siem}"); self.siem_verify_ssl_check.setToolTip("Uncheck for self-signed certs (SECURITY RISK)."); self.siem_refresh_input.setToolTip("Refresh interval (min). 0 to disable."); siem_layout.addRow("API URL:", self.siem_url_input); siem_layout.addRow("Auth Token/Key/Pass:", self.siem_auth_token_input); siem_layout.addRow("Auth Username:", self.siem_username_input); siem_layout.addRow(self.siem_verify_ssl_check); siem_layout.addRow("Refresh Interval (min):", self.siem_refresh_input); self.siem_splunk_query_input = QTextEdit(); self.siem_splunk_query_input.setFixedHeight(60); self.siem_splunk_auth_header_combo = QComboBox(); self.siem_splunk_auth_header_combo.addItems(["Bearer", "Splunk"]); siem_layout.addRow(QLabel("Auth Header <font color='#aaa'>(Splunk)</font>:"), self.siem_splunk_auth_header_combo); siem_layout.addRow(QLabel("Search Query <font color='#aaa'>(Splunk)</font>:"), self.siem_splunk_query_input); self.siem_elastic_index_input = QLineEdit(); self.siem_elastic_query_input = QTextEdit(); self.siem_elastic_query_input.setFixedHeight(60); self.siem_elastic_auth_combo = QComboBox(); self.siem_elastic_auth_combo.addItems(["api_key", "basic"]); siem_layout.addRow(QLabel("Index Pattern <font color='#aaa'>(Elastic)</font>:"), self.siem_elastic_index_input); siem_layout.addRow(QLabel("Query DSL <font color='#aaa'>(Elastic)</font>:"), self.siem_elastic_query_input); siem_layout.addRow(QLabel("Auth Method <font color='#aaa'>(Elastic)</font>:"), self.siem_elastic_auth_combo); layout.addWidget(siem_group)
        # --- SOAR Section ---
        soar_group = QGroupBox("SOAR Integration"); soar_layout = QFormLayout(soar_group); soar_layout.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow); soar_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight); soar_layout.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows); soar_layout.setSpacing(10); self.soar_enabled_check = QCheckBox("Enable SOAR"); soar_layout.addRow(self.soar_enabled_check); self.soar_type_combo = QComboBox(); self.soar_type_combo.addItems(list(SOAR_TYPE_MAP.keys())); soar_layout.addRow("SOAR Type:", self.soar_type_combo); self.soar_url_input = QLineEdit(); self.soar_auth_token_input = QLineEdit(); self.soar_auth_token_input.setEchoMode(QLineEdit.EchoMode.Password); self.soar_verify_ssl_check = QCheckBox("Verify SSL"); env_tooltip_soar = "Use 'ENV:VAR_NAME' for environment variable."; self.soar_url_input.setToolTip(f"API URL.\n{env_tooltip_soar}"); self.soar_auth_token_input.setToolTip(f"API Token/Key.\n{env_tooltip_soar}"); self.soar_verify_ssl_check.setToolTip("Uncheck for self-signed certs (SECURITY RISK)."); soar_layout.addRow("API URL:", self.soar_url_input); soar_layout.addRow("Auth Token/Key:", self.soar_auth_token_input); soar_layout.addRow(self.soar_verify_ssl_check); self.soar_xsoar_auth_header_input = QLineEdit(); self.soar_xsoar_auth_prefix_input = QLineEdit(); soar_layout.addRow(QLabel("Auth Header <font color='#aaa'>(XSOAR)</font>:"), self.soar_xsoar_auth_header_input); soar_layout.addRow(QLabel("Auth Value Prefix <font color='#aaa'>(XSOAR)</font>:"), self.soar_xsoar_auth_prefix_input); layout.addWidget(soar_group)
        layout.addStretch()
        # --- Apply Button ---
        main_settings_layout = QVBoxLayout(settings_tab); main_settings_layout.addWidget(scroll_area); apply_btn = QPushButton(QIcon.fromTheme("document-save", self._create_default_icon()), " Apply && Save All Settings"); apply_btn.setToolTip("Apply changes, restart connections, and save config."); apply_btn.setFixedHeight(35); apply_btn.clicked.connect(self.apply_and_save_settings); main_settings_layout.addWidget(apply_btn, 0, Qt.AlignmentFlag.AlignRight)
        self.refresh_settings_ui(); self.tabs.addTab(settings_tab, QIcon.fromTheme("preferences-system", self._create_default_icon("app")), "Settings"); logger.debug("Settings tab created.")

    def update_mfa_status_label(self):
        if not hasattr(self, 'mfa_status_label'): return
        try: secret = get_totp_secret();
             if secret: self.mfa_status_label.setText("<b>Status:</b> <font color='green'>Enabled</font>."); self.manage_mfa_button.setText("Manage 2FA...")
             else: self.mfa_status_label.setText("<b>Status:</b> <font color='orange'>Disabled</font>."); self.manage_mfa_button.setText("Setup 2FA...")
             self.manage_mfa_button.setEnabled(True)
        except KeyringError as e: self.mfa_status_label.setText(f"<b>Status:</b> <font color='red'>Keyring Error:</font> {e}"); self.manage_mfa_button.setEnabled(False)
        except Exception as e: self.mfa_status_label.setText(f"<b>Status:</b> <font color='red'>Error:</font> Check failed ({type(e).__name__})."); self.manage_mfa_button.setEnabled(False)

    def open_mfa_dialog(self): dialog = MFASetupDialog(self); dialog.exec(); self.update_mfa_status_label()

    def refresh_settings_ui(self):
         logger.debug("Refreshing settings UI...")
         self.update_mfa_status_label()
         # Populate Camera List
         self.camera_list_widget.clear(); current_cam_raw_names = set();
         for config in self.app_config.get('cameras', []):
             raw_name = config.get('name');
             if raw_name: item = QListWidgetItem(f" {raw_name}"); icon_name = "camera-video" if config.get('onvif') else "network-wired"; item.setIcon(QIcon.fromTheme(icon_name, self._create_default_icon("camera"))); item.setData(Qt.ItemDataRole.UserRole, config); self.camera_list_widget.addItem(item); current_cam_raw_names.add(raw_name)
         # Populate Sensor List
         self.sensor_list_widget.clear(); current_sensor_ids = set()
         for config in self.app_config.get('fence_sensors', []):
             sensor_id = config.get('id'); sensor_name = config.get('name', sensor_id)
             if sensor_id: item = QListWidgetItem(f" {sensor_name} ({sensor_id})"); item.setIcon(QIcon.fromTheme("preferences-system-network", self._create_default_icon("app"))); item.setData(Qt.ItemDataRole.UserRole, config); self.sensor_list_widget.addItem(item); current_sensor_ids.add(sensor_id)
         # Populate Sensor Input Fields
         sensor_input_conf = self.app_config.get('sensor_input', {}); self.sensor_input_enabled_check.setChecked(sensor_input_conf.get('enabled', False)); self.sensor_input_path_input.setText(sensor_input_conf.get('path', '')); self.sensor_input_interval_input.setValue(sensor_input_conf.get('read_interval_ms', 2000))
         # Populate SIEM Fields
         siem_config = self.app_config.get('siem', {}); self.siem_enabled_check.setChecked(siem_config.get('enabled', False)); current_siem_type = siem_config.get('type', 'Splunk'); type_index = self.siem_type_combo.findText(current_siem_type, Qt.MatchFlag.MatchFixedString); self.siem_type_combo.setCurrentIndex(type_index if type_index >= 0 else 0)
         def set_line_edit_text_or_placeholder(line_edit: QLineEdit, value: Any, placeholder: str = ""):
             if isinstance(value, str) and value.startswith("ENV:"): line_edit.setPlaceholderText(f"Using ENV: {value[4:]}"); line_edit.setText("")
             else: line_edit.setPlaceholderText(placeholder if value is None or value == "" else ""); line_edit.setText(str(value) if value is not None else "")
         set_line_edit_text_or_placeholder(self.siem_url_input, siem_config.get('api_url'), "e.g., https://siem:8089"); set_line_edit_text_or_placeholder(self.siem_auth_token_input, siem_config.get('auth_token'), "Token/Key/Pass"); set_line_edit_text_or_placeholder(self.siem_username_input, siem_config.get('username'), "(Optional) Basic Auth User"); self.siem_verify_ssl_check.setChecked(siem_config.get('verify_ssl', True)); self.siem_refresh_input.setText(str(siem_config.get('refresh_interval_min', 15)))
         auth_header_index = self.siem_splunk_auth_header_combo.findText(siem_config.get('auth_header_type', 'Bearer')); self.siem_splunk_auth_header_combo.setCurrentIndex(auth_header_index if auth_header_index >= 0 else 0); self.siem_splunk_query_input.setPlainText(siem_config.get('splunk_query', '')); self.siem_elastic_index_input.setText(siem_config.get('elastic_index', 'security-alerts-*')); self.siem_elastic_query_input.setPlainText(siem_config.get('elastic_query_dsl', '')); auth_method_index = self.siem_elastic_auth_combo.findText(siem_config.get('elastic_auth_method', 'api_key')); self.siem_elastic_auth_combo.setCurrentIndex(auth_method_index if auth_method_index >= 0 else 0)
         # Populate SOAR Fields
         soar_config = self.app_config.get('soar', {}); self.soar_enabled_check.setChecked(soar_config.get('enabled', False)); current_soar_type = soar_config.get('type', 'SplunkSOAR'); soar_type_index = self.soar_type_combo.findText(current_soar_type, Qt.MatchFlag.MatchFixedString); self.soar_type_combo.setCurrentIndex(soar_type_index if soar_type_index >= 0 else 0); set_line_edit_text_or_placeholder(self.soar_url_input, soar_config.get('api_url'), "e.g., https://soar.example.com"); set_line_edit_text_or_placeholder(self.soar_auth_token_input, soar_config.get('auth_token'), "API Token/Key"); self.soar_verify_ssl_check.setChecked(soar_config.get('verify_ssl', True)); self.soar_xsoar_auth_header_input.setText(soar_config.get('auth_header_name', 'Authorization')); self.soar_xsoar_auth_prefix_input.setText(soar_config.get('auth_value_prefix', ''))
         # Prune Map Positions
         map_positions = self.app_config['map_view'].get('item_positions', {}); active_item_ids = current_cam_raw_names.union(current_sensor_ids) # WRONG: need sanitized cam names
         active_sanitized_cam_names = {sanitize_filename(name) for name in current_cam_raw_names}
         active_item_ids = active_sanitized_cam_names.union(current_sensor_ids)
         if isinstance(map_positions, dict):
              current_map_keys = set(map_positions.keys()); stale_map_keys = current_map_keys - active_item_ids
              if stale_map_keys: logger.info(f"Refresh Settings UI: Pruning stale map positions: {stale_map_keys}");
                   for key in stale_map_keys: map_positions.pop(key, None); self.mark_settings_dirty()
         else: self.app_config['map_view']['item_positions'] = {}
         logger.debug("Settings UI refresh complete.")

    def add_camera_config(self):
        logger.debug("Add Camera clicked."); dialog = CameraConfigDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            if new_config := dialog.get_config():
                 new_raw_name = new_config['name'];
                 if new_raw_name in {cfg.get('name') for cfg in self.app_config['cameras']}: QMessageBox.warning(self, "Duplicate Name", f"Camera '{new_raw_name}' already exists."); return
                 logger.info(f"Adding camera: {new_raw_name}"); self.app_config['cameras'].append(new_config); self.refresh_settings_ui(); self.mark_settings_dirty(); self.notifications.show_message(f"Camera '{new_raw_name}' added. Apply to activate.", level="info")

    def edit_camera_config(self):
        current_item = self.camera_list_widget.currentItem();
        if not current_item: QMessageBox.information(self, "Edit Camera", "Select camera to edit."); return
        current_config = current_item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(current_config, dict): logger.error(f"Invalid config data: {current_item.text()}."); QMessageBox.critical(self, "Error", "Internal error: Cannot get camera config."); return
        original_raw_name = current_config.get('name'); logger.debug(f"Editing camera: {original_raw_name}"); dialog = CameraConfigDialog(self, config=current_config)
        if dialog.exec() == QDialog.DialogCode.Accepted:
             if updated_config := dialog.get_config():
                  new_raw_name = updated_config.get('name')
                  if original_raw_name != new_raw_name:
                      existing_names = {cfg.get('name') for cfg in self.app_config['cameras'] if cfg.get('name') != original_raw_name};
                      if new_raw_name in existing_names: QMessageBox.warning(self, "Duplicate Name", f"Another camera named '{new_raw_name}' exists."); return
                  found_index = -1;
                  for i, cfg in enumerate(self.app_config['cameras']):
                      if cfg.get('name') == original_raw_name: found_index = i; break
                  if found_index != -1:
                       logger.info(f"Updating config for '{original_raw_name}' -> '{new_raw_name}'"); self.app_config['cameras'][found_index] = updated_config
                       if original_raw_name != new_raw_name: self._handle_item_rename_in_map(sanitize_filename(original_raw_name), sanitize_filename(new_raw_name))
                       self.refresh_settings_ui(); self.mark_settings_dirty(); self.notifications.show_message(f"Camera '{new_raw_name}' updated. Apply to activate.", level="info")
                  else: logger.error(f"Error: Cannot find camera '{original_raw_name}' during edit."); QMessageBox.critical(self, "Error", "Internal update error.")

    def remove_camera_config(self):
        current_item = self.camera_list_widget.currentItem();
        if not current_item: QMessageBox.information(self, "Remove Camera", "Select camera to remove."); return
        config_data = current_item.data(Qt.ItemDataRole.UserRole); camera_raw_name = config_data.get('name') if isinstance(config_data, dict) else None
        if not camera_raw_name: logger.error("Failed get camera name for removal."); QMessageBox.critical(self, "Error", "Cannot identify camera."); return
        reply = QMessageBox.question(self, "Confirm Removal", f"Remove camera '{camera_raw_name}'?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            logger.info(f"Removing camera: {camera_raw_name}"); initial_len = len(self.app_config['cameras'])
            self.app_config['cameras'] = [cfg for cfg in self.app_config['cameras'] if cfg.get('name') != camera_raw_name]
            if len(self.app_config['cameras']) < initial_len: self._handle_item_remove_from_map(sanitize_filename(camera_raw_name)); self.refresh_settings_ui(); self.mark_settings_dirty(); self.notifications.show_message(f"Camera '{camera_raw_name}' removed. Apply changes.", level="info")
            else: logger.error(f"Error: Camera '{camera_raw_name}' not found for removal."); QMessageBox.warning(self, "Error", "Internal removal error.")

    def add_sensor_config(self):
        logger.debug("Add Sensor clicked.")
        existing_ids = {s.get('id') for s in self.app_config.get('fence_sensors', [])}
        available_cameras = self.app_config.get('cameras', [])
        dialog = SensorConfigDialog(self, existing_sensor_ids=existing_ids, available_cameras=available_cameras)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            if new_config := dialog.get_config():
                 sensor_id = new_config['id'] # ID uniqueness already checked in dialog
                 logger.info(f"Adding new sensor: {sensor_id} ({new_config.get('name')})")
                 self.app_config['fence_sensors'].append(new_config)
                 self.refresh_settings_ui()
                 self.mark_settings_dirty()
                 self.notifications.show_message(f"Sensor '{new_config.get('name')}' added. Apply to activate.", level="info")

    def edit_sensor_config(self):
        current_item = self.sensor_list_widget.currentItem()
        if not current_item: QMessageBox.information(self, "Edit Sensor", "Select a sensor to edit."); return
        current_config = current_item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(current_config, dict): logger.error(f"Invalid sensor config data: {current_item.text()}."); QMessageBox.critical(self, "Error", "Internal error: Cannot get sensor config."); return
        sensor_id = current_config.get('id')
        logger.debug(f"Editing sensor: {sensor_id}")
        existing_ids = {s.get('id') for s in self.app_config.get('fence_sensors', [])} # Needed by dialog logic
        available_cameras = self.app_config.get('cameras', [])
        dialog = SensorConfigDialog(self, config=current_config, existing_sensor_ids=existing_ids, available_cameras=available_cameras)
        if dialog.exec() == QDialog.DialogCode.Accepted:
             if updated_config := dialog.get_config():
                  found_index = -1
                  for i, cfg in enumerate(self.app_config['fence_sensors']):
                      if cfg.get('id') == sensor_id: found_index = i; break
                  if found_index != -1:
                       logger.info(f"Updating config for sensor '{sensor_id}'")
                       self.app_config['fence_sensors'][found_index] = updated_config
                       # Check if location changed, if so, mark dirty (marker pos handled separately)
                       if self.original_config.get('location') != updated_config.get('location'): self.mark_settings_dirty()
                       self.refresh_settings_ui() # Refresh list display
                       self.mark_settings_dirty() # Mark dirty because list content changed
                       self.notifications.show_message(f"Sensor '{updated_config.get('name')}' updated. Apply to activate changes.", level="info")
                  else: logger.error(f"Error: Cannot find sensor '{sensor_id}' during edit."); QMessageBox.critical(self, "Error", "Internal sensor update error.")

    def remove_sensor_config(self):
        current_item = self.sensor_list_widget.currentItem()
        if not current_item: QMessageBox.information(self, "Remove Sensor", "Select a sensor to remove."); return
        config_data = current_item.data(Qt.ItemDataRole.UserRole); sensor_id = config_data.get('id') if isinstance(config_data, dict) else None
        if not sensor_id: logger.error("Failed to get sensor ID for removal."); QMessageBox.critical(self, "Error", "Cannot identify sensor."); return
        sensor_name = config_data.get('name', sensor_id)
        reply = QMessageBox.question(self, "Confirm Removal", f"Remove sensor '{sensor_name}' ({sensor_id})?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            logger.info(f"Removing sensor: {sensor_id}"); initial_len = len(self.app_config['fence_sensors'])
            self.app_config['fence_sensors'] = [cfg for cfg in self.app_config['fence_sensors'] if cfg.get('id') != sensor_id]
            if len(self.app_config['fence_sensors']) < initial_len:
                 self._handle_item_remove_from_map(sensor_id)
                 self.refresh_settings_ui(); self.mark_settings_dirty(); self.notifications.show_message(f"Sensor '{sensor_name}' removed. Apply changes.", level="info")
            else: logger.error(f"Error: Sensor '{sensor_id}' not found for removal."); QMessageBox.warning(self, "Error", "Internal sensor removal error.")


    def _handle_item_rename_in_map(self, old_item_id: str, new_item_id: str):
        # Handles renaming for cameras OR sensors (if sensor IDs could change, but currently they don't)
        if 'map_view' in self.app_config and isinstance(positions := self.app_config['map_view'].get('item_positions', {}), dict):
            if old_item_id in positions:
                positions[new_item_id] = positions.pop(old_item_id)
                logger.debug(f"Updated map position key: '{old_item_id}' -> '{new_item_id}'."); self.mark_settings_dirty()

    def _handle_item_remove_from_map(self, item_id: str):
        # Handles removal for cameras OR sensors
        if 'map_view' in self.app_config and isinstance(positions := self.app_config['map_view'].get('item_positions', {}), dict):
            if item_id in positions:
                positions.pop(item_id); logger.debug(f"Removed map position for item '{item_id}'."); self.mark_settings_dirty()

    def apply_and_save_settings(self):
        logger.info("Apply & Save Settings clicked...")
        try:
            # Get original configs for ENV var resolution helper
            original_siem_config = self.app_config.get('siem', {}); original_soar_config = self.app_config.get('soar', {});
            # Helper to get UI value or keep ENV string
            def get_ui_value_or_env(line_edit: QLineEdit, original_config_value: Any) -> Optional[str]:
                text = line_edit.text().strip()
                if not text and isinstance(original_config_value, str) and original_config_value.startswith("ENV:"): return original_config_value
                elif text.upper().startswith("ENV:"): var_name = text[4:];
                     if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', var_name): return f"ENV:{var_name}"
                     else: raise ValueError(f"Invalid environment variable format: '{text}'.")
                else: return text if text else None

            # Update SIEM Config from UI
            siem_conf = {}; siem_conf['enabled'] = self.siem_enabled_check.isChecked(); siem_conf['type'] = self.siem_type_combo.currentText(); siem_conf['api_url'] = get_ui_value_or_env(self.siem_url_input, original_siem_config.get('api_url')); siem_conf['auth_token'] = get_ui_value_or_env(self.siem_auth_token_input, original_siem_config.get('auth_token')); siem_conf['username'] = get_ui_value_or_env(self.siem_username_input, original_siem_config.get('username')); siem_conf['verify_ssl'] = self.siem_verify_ssl_check.isChecked();
            try: refresh_text = self.siem_refresh_input.text().strip(); refresh_min = int(refresh_text) if refresh_text else 0; siem_conf['refresh_interval_min'] = max(0, min(refresh_min, 1440))
            except (ValueError, TypeError): raise ValueError("Invalid SIEM Refresh Interval.")
            siem_conf['auth_header_type'] = self.siem_splunk_auth_header_combo.currentText(); siem_conf['splunk_query'] = self.siem_splunk_query_input.toPlainText().strip(); siem_conf['elastic_index'] = self.siem_elastic_index_input.text().strip(); siem_conf['elastic_query_dsl'] = self.siem_elastic_query_input.toPlainText().strip(); siem_conf['elastic_auth_method'] = self.siem_elastic_auth_combo.currentText()

            # Update SOAR Config from UI
            soar_conf = {}; soar_conf['enabled'] = self.soar_enabled_check.isChecked(); soar_conf['type'] = self.soar_type_combo.currentText(); soar_conf['api_url'] = get_ui_value_or_env(self.soar_url_input, original_soar_config.get('api_url')); soar_conf['auth_token'] = get_ui_value_or_env(self.soar_auth_token_input, original_soar_config.get('auth_token')); soar_conf['verify_ssl'] = self.soar_verify_ssl_check.isChecked(); soar_conf['auth_header_name'] = self.soar_xsoar_auth_header_input.text().strip(); soar_conf['auth_value_prefix'] = self.soar_xsoar_auth_prefix_input.text().strip()

            # Update Sensor Input Config from UI
            sensor_input_conf = {}; sensor_input_conf['enabled'] = self.sensor_input_enabled_check.isChecked(); sensor_input_conf['type'] = self.sensor_input_type_combo.currentText(); sensor_input_conf['path'] = self.sensor_input_path_input.text().strip(); sensor_input_conf['read_interval_ms'] = self.sensor_input_interval_input.value()
            if not sensor_input_conf['path'] and sensor_input_conf['enabled']: raise ValueError("Sensor log file path cannot be empty if sensor monitoring is enabled.")

            # --- Update main config dict ---
            # Camera list and Sensor list are modified directly by add/edit/remove
            # Map positions are updated by marker moves or _add_markers_for_unplaced_items
            self.app_config['siem'] = siem_conf
            self.app_config['soar'] = soar_conf
            self.app_config['sensor_input'] = sensor_input_conf

        except ValueError as e: QMessageBox.warning(self, "Input Error", f"Failed to apply settings: {e}"); return

        # --- Save Configuration ---
        if self.save_config():
             self.notifications.show_message("Applying changes & restarting...", level="info", duration=1500); QApplication.processEvents()
             # Reinitialize system components
             self.stop_all_threads() # Stop cameras AND sensor thread
             self.init_system()      # Re-init all with new config
             self.update_siem_timer_interval() # Restart SIEM timer
             self.recreate_monitor_tab()     # Rebuild UI
             # Map markers updated within init_system
             self.notifications.show_message("Settings applied and saved!", level="success", duration=3500)
             self.mark_settings_dirty(False)
        else: QMessageBox.critical(self, "Save Error", "Failed to save config file.\nChanges not fully applied.")


    # ==================== Theme & Misc Methods ====================
    @staticmethod
    def apply_dark_theme(instance=None):
        logger.debug("Applying dark theme...")
        dp=QPalette();WINDOW_BG=QColor(53,53,53);WINDOW_TEXT=QColor(230,230,230);BASE=QColor(35,35,35);ALT_BASE=QColor(45,45,45);TOOLTIP_BG=QColor(25,25,25);TOOLTIP_TEXT=QColor(230,230,230);TEXT=QColor(220,220,220);BUTTON_BG=QColor(66,66,66);BUTTON_TEXT=QColor(230,230,230);BUTTON_DISABLED_TEXT=QColor(127,127,127);BRIGHT_TEXT=QColor(255,80,80);HIGHLIGHT=QColor(42,130,218);HIGHLIGHTED_TEXT=QColor(255,255,255);HIGHLIGHT_DISABLED=QColor(80,80,80);LINK=QColor(80,160,240);LINK_VISITED=QColor(160,100,220);BORDER_COLOR=QColor(80,80,80)
        dp.setColor(QPalette.ColorRole.Window,WINDOW_BG);dp.setColor(QPalette.ColorRole.WindowText,WINDOW_TEXT);dp.setColor(QPalette.ColorRole.Base,BASE);dp.setColor(QPalette.ColorRole.AlternateBase,ALT_BASE);dp.setColor(QPalette.ColorRole.ToolTipBase,TOOLTIP_BG);dp.setColor(QPalette.ColorRole.ToolTipText,TOOLTIP_TEXT);dp.setColor(QPalette.ColorRole.Text,TEXT);dp.setColor(QPalette.ColorRole.Button,BUTTON_BG);dp.setColor(QPalette.ColorRole.ButtonText,BUTTON_TEXT);dp.setColor(QPalette.ColorGroup.Disabled,QPalette.ColorRole.ButtonText,BUTTON_DISABLED_TEXT);dp.setColor(QPalette.ColorRole.BrightText,BRIGHT_TEXT);dp.setColor(QPalette.ColorRole.Highlight,HIGHLIGHT);dp.setColor(QPalette.ColorRole.HighlightedText,HIGHLIGHTED_TEXT);dp.setColor(QPalette.ColorGroup.Disabled,QPalette.ColorRole.Highlight,HIGHLIGHT_DISABLED);dp.setColor(QPalette.ColorRole.Link,LINK);dp.setColor(QPalette.ColorRole.LinkVisited,LINK_VISITED)
        app=QApplication.instance();app.setPalette(dp)if app else None
        stylesheet=f"""QWidget{{font-size:9pt;}}QMainWindow,QDialog{{background-color:{WINDOW_BG.name()};}}QToolTip{{color:{TOOLTIP_TEXT.name()};background-color:{TOOLTIP_BG.name()};border:1px solid #3b3b3b;padding:5px;border-radius:3px;}}QGroupBox{{font-weight:bold;color:#ddd;border:1px solid {BORDER_COLOR.name()};border-radius:6px;margin-top:0.6em;padding:0.8em 0.5em 0.5em 0.5em;}}QGroupBox::title{{subcontrol-origin:margin;subcontrol-position:top left;padding:0 5px;left:10px;color:#ccc;}}QTabWidget::pane{{border:1px solid {BORDER_COLOR.darker(110).name()};border-radius:3px;margin-top:-1px;background-color:{BASE.name()};}}QTabBar::tab{{background:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #666,stop:1 #555);border:1px solid {BORDER_COLOR.darker(110).name()};border-bottom:none;border-top-left-radius:5px;border-top-right-radius:5px;min-width:10ex;padding:6px 12px;margin-right:2px;color:#ccc;}}QTabBar::tab:selected{{background:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #4a4a4a,stop:1 {BASE.name()});border-color:{BORDER_COLOR.darker(110).name()};color:#fff;font-weight:bold;}}QTabBar::tab:!selected{{margin-top:2px;background:#555;}}QTabBar::tab:!selected:hover{{background:#777;color:#fff;}}QPushButton{{color:{BUTTON_TEXT.name()};background-color:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #666,stop:1 #5a5a5a);border:1px solid {BORDER_COLOR.name()};border-radius:4px;padding:6px 12px;min-width:60px;}}QPushButton:hover{{background-color:#777;border-color:{BORDER_COLOR.lighter(110).name()};}}QPushButton:pressed{{background-color:#505050;}}QPushButton:checked{{background-color:{HIGHLIGHT.name()};border-color:{HIGHLIGHT.darker(120).name()};color:{HIGHLIGHTED_TEXT.name()};}}QPushButton:disabled{{color:{BUTTON_DISABLED_TEXT.name()};background-color:#444;border-color:#555;}}QLineEdit,QComboBox,QAbstractSpinBox,QDoubleSpinBox,QSpinBox{{color:{TEXT.name()};background-color:{ALT_BASE.name()};border:1px solid {BORDER_COLOR.name()};border-radius:4px;padding:4px 6px;}}QLineEdit:placeholder-text{{color:#888;}}QTextEdit,QPlainTextEdit{{color:{TEXT.name()};background-color:{ALT_BASE.name()};border:1px solid {BORDER_COLOR.name()};border-radius:4px;padding:5px;}}QComboBox::drop-down{{border:none;subcontrol-origin:padding;subcontrol-position:top right;width:18px;}}QListWidget{{color:{TEXT.name()};background-color:{BASE.name()};border:1px solid {BORDER_COLOR.name()};border-radius:4px;padding:2px;alternate-background-color:{ALT_BASE.name()};}}QListWidget::item{{padding:4px 0px;}}QListWidget::item:selected{{background-color:{HIGHLIGHT.name()};color:{HIGHLIGHTED_TEXT.name()};border:none;}}QListWidget::item:selected:!active{{background-color:{HIGHLIGHT.darker(120).name()};}}QCheckBox{{spacing:8px;}}QCheckBox::indicator{{width:16px;height:16px;border:1px solid {BORDER_COLOR.name()};border-radius:4px;background-color:{ALT_BASE.name()};}}QCheckBox::indicator:checked{{background-color:{HIGHLIGHT.name()};border-color:{HIGHLIGHT.darker(120).name()};}}QCheckBox::indicator:disabled{{background-color:#444;border-color:#555;}}QToolBar{{background-color:{WINDOW_BG.darker(110).name()};border:none;padding:3px;spacing:4px;}}QToolButton{{background-color:transparent;border:none;padding:4px;border-radius:4px;color:{BUTTON_TEXT.name()};}}QToolButton:hover{{background-color:{BUTTON_BG.lighter(120).name()};}}QToolButton:pressed{{background-color:{BUTTON_BG.name()};}}QToolButton:checked{{background-color:{HIGHLIGHT.name()};border:1px solid {HIGHLIGHT.darker(120).name()};color:{HIGHLIGHTED_TEXT.name()};}}QStatusBar{{color:#bbb;}}QStatusBar::item{{border:none;}}QGraphicsView{{border:1px solid {BORDER_COLOR.name()};border-radius:3px;}}QScrollArea{{border:none;}}QScrollBar:vertical{{border:1px solid {BORDER_COLOR.name()};background:{BASE.name()};width:12px;margin:0px;}}QScrollBar::handle:vertical{{background:{BUTTON_BG.name()};min-height:20px;border-radius:5px;}}QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{height:0px;background:none;}}QScrollBar:horizontal{{border:1px solid {BORDER_COLOR.name()};background:{BASE.name()};height:12px;margin:0px;}}QScrollBar::handle:horizontal{{background:{BUTTON_BG.name()};min-width:20px;border-radius:5px;}}QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal{{width:0px;background:none;}}"""
        if app: app.setStyleSheet(stylesheet); logger.debug("Dark theme applied.")

    def show_about(self):
        try: py_ver = platform.python_version()
        except: py_ver = "N/A"
        try: qt_ver = Qt.PYQT_VERSION_STR
        except: qt_ver = "N/A"
        try: cv_ver = cv2.__version__
        except: cv_ver = "N/A"
        try: import importlib.metadata; onvif_ver = importlib.metadata.version('onvif_zeep')
        except: onvif_ver = "N/A"
        try: pyotp_ver = importlib.metadata.version('pyotp')
        except: pyotp_ver = "N/A"
        try: keyring_ver = importlib.metadata.version('keyring')
        except: keyring_ver = "N/A"
        try: qrcode_ver = importlib.metadata.version('qrcode')
        except: qrcode_ver = "N/A"

        app_version = "1.6.0-sensors" # Version bump
        about_text = f"""<h2>Security Monitor Pro (Versatile + Sensors)</h2><p>Version: {app_version}</p><p>Comprehensive security monitoring system.</p><hr><p><b>Runtime Information:</b></p><ul><li>Python: {py_ver}</li><li>PyQt: {qt_ver}</li><li>OpenCV: {cv_ver}</li><li>ONVIF-Zeep: {onvif_ver}</li><li>PyOTP: {pyotp_ver}</li><li>Keyring: {keyring_ver}</li><li>QRCode: {qrcode_ver}</li><li>Platform: {platform.system()} ({platform.release()})</li></ul><hr><p><b>Features:</b></p><ul><li><b>MFA/2FA (TOTP) for Startup Security</b></li><li>RTSP & ONVIF (PTZ) Support</li><li><b>Fence Sensor Integration (Log File Input)</b></li><li>Configurable SIEM Integration (Splunk, Elasticsearch*)</li><li>Configurable SOAR Integration (SplunkSOAR*, CortexXSOAR*)</li><li>OpenCV Motion Detection</li><li>Visual Map View & Layout Editing (Cameras & Sensors)</li><li>Dynamic Camera & Sensor Configuration</li><li>Dark Mode UI</li><li>Snapshot Saving</li><li>Optional Auto Dependency Install</li><li>Environment Variable Support for Credentials</li></ul><p style='font-size:8pt;color:#aaa;'><i>* Basic SIEM/SOAR integration provided. Sensor input currently via log file.<br>Functionality depends on camera/sensor hardware & network configuration.<br>Review security considerations in documentation/code comments.</i></p>"""
        QMessageBox.about(self, f"About Security Monitor Pro v{app_version}", about_text)

    def resizeEvent(self, event: 'QResizeEvent'):
        super().resizeEvent(event)
        if hasattr(self, 'notifications') and self.notifications and self.notifications.isVisible():
            parent_width = self.central_widget.width(); notif_width = self.notifications.width(); new_x = (parent_width - notif_width) // 2; current_geom = self.notifications.geometry()
            if current_geom.isValid(): current_y = current_geom.y(); self.notifications.move(new_x, max(20, current_y))

    def check_unsaved_changes(self, action_desc: str = "perform this action") -> bool:
         if not self._settings_dirty: return True
         reply = QMessageBox.question(self, "Unsaved Changes", f"Unsaved configuration changes.\nSave before {action_desc}?", QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Cancel)
         if reply == QMessageBox.StandardButton.Save: return self.save_config()
         elif reply == QMessageBox.StandardButton.Discard:
             logger.info("Discarding unsaved changes by reloading config.")
             try: current_filepath = self.config_filepath; self.load_config(current_filepath); self.refresh_settings_ui(); self.update_map_markers(); self.mark_settings_dirty(False); logger.info("Config reloaded."); return True
             except Exception as e: logger.error(f"Error reloading config: {e}", exc_info=True); QMessageBox.critical(self, "Error", f"Failed to reload config: {e}"); return False
         else: logger.info(f"Action '{action_desc}' cancelled."); return False

    def closeEvent(self, event: 'QCloseEvent'):
        logger.info("Close event received. Shutting down...");
        if not self.check_unsaved_changes("exit the application"): event.ignore(); logger.info("Close cancelled."); return
        if hasattr(self, 'status_bar'): self.status_bar.showMessage("Shutting down..."); QApplication.processEvents()
        if hasattr(self, 'siem_refresh_timer'): self.siem_refresh_timer.stop()
        if hasattr(self, 'notifications._hide_timer'): self.notifications._hide_timer.stop() # Stop notification timer
        self.stop_all_threads() # Stop cameras and sensor thread
        logger.info("Shutdown sequence complete. Exiting.")
        event.accept()


# ==================== MFA STARTUP CHECK ====================
def perform_startup_mfa_check() -> bool:
    """Checks if MFA is enabled and prompts for verification if needed."""
    try:
        secret = get_totp_secret()
        if secret:
            logger.info("MFA enabled. Prompting for verification...")
            dialog = TOTPVerificationDialog(parent=None)
            if dialog.exec() == QDialog.DialogCode.Accepted and dialog.verification_successful:
                logger.info("Startup MFA successful.")
                return True
            else:
                logger.critical("Startup MFA failed or cancelled. Exiting.")
                QMessageBox.critical(None, "MFA Required", "Authentication failed or cancelled.\nApplication exiting.")
                return False
        else:
            logger.info("MFA not enabled. Proceeding.")
            return True
    except KeyringError as e:
        logger.critical(f"Keyring error during startup MFA check: {e}. Cannot proceed.")
        QMessageBox.critical(None, "MFA Error", f"Keyring error checking MFA status:\n{e}\nCheck system credential store. Cannot start securely.")
        return False
    except Exception as e:
         logger.critical(f"Unexpected error during MFA check: {e}", exc_info=True)
         QMessageBox.critical(None, "Fatal Error", f"Unexpected error during MFA check:\n{e}\nApplication exiting.")
         return False

# ==================== MAIN EXECUTION ====================
if __name__ == "__main__":
    if platform.system() == "Windows": os.environ["QT_ENABLE_HIGHDPI_SCALING"] = "1"
    QApplication.setApplicationName("SecurityMonitorPro"); QApplication.setOrganizationName("UserProject")
    app = QApplication(sys.argv)
    app.setStyle('Fusion')

    # Apply dark theme globally BEFORE any dialogs/windows
    SecurityMonitorApp.apply_dark_theme(None)

    # Perform MFA Check BEFORE creating main window
    if not perform_startup_mfa_check():
        sys.exit(1)

    # Proceed to create main window
    window = None
    try:
        logger.info("MFA Check Passed. Creating main window...")
        window = SecurityMonitorApp()
        window.show()
        logger.info("Application window shown. Starting event loop.")
        exit_code = app.exec()
        logger.info(f"Application event loop finished. Exiting code {exit_code}.")
        sys.exit(exit_code)
    except Exception as e:
         logger.critical(f"FATAL ERROR: Unhandled exception in main execution: {e}", exc_info=True)
         error_message = f"Critical error occurred:\n{type(e).__name__}\n\nApplication exiting. Check logs."
         try:
              if QApplication.instance(): QMessageBox.critical(None, "Fatal Application Error", error_message)
              else: print(f"FATAL ERROR: {error_message}\nDETAILS: {e}", file=sys.stderr)
         except Exception as display_err: print(f"FATAL ERROR: {error_message}\nDETAILS: {e}\n(Display error failed: {display_err})", file=sys.stderr)
         sys.exit(1)

# --- END OF FILE gptdemo_with_sensors.py ---
```

---

**3. דוגמה לקובץ התצורה החדש (`config_with_sensors.yaml`)**

```yaml
# Example Configuration File for Security Monitor Pro (Versatile + Sensors)

# --- Camera Definitions ---
cameras:
  - name: "Camera North Gate"   # Raw name for display
    onvif: true              # Use ONVIF protocol
    host: "192.168.1.101"    # ONVIF Host IP
    port: 80                 # ONVIF Port (often 80)
    user: "admin"            # ONVIF Username (use ENV:CAM1_USER for env var)
    password: "ENV:CAM1_PASS" # ONVIF Password (use ENV:CAM1_PASS for env var)
    motion_threshold: 1000   # Larger value = less sensitive motion detection (0=disabled)
  - name: "Camera Overview North"
    onvif: false             # Use RTSP URL directly
    url: "rtsp://user:pass@192.168.1.102:554/stream1" # RTSP URL (can use ENV:)
    motion_threshold: 500
  - name: "Camera West Gate Zoom"
    onvif: true
    host: "192.168.1.103"
    port: 80
    user: "onvif_user"
    password: "complexpassword123"
    motion_threshold: 0 # Motion disabled for this camera

# --- Fence Sensor Definitions ---
fence_sensors:
  - id: "FenceNorth01"            # Unique internal ID (alphanumeric, _, -)
    name: "גדר צפונית - אזור 1"   # Display Name
    type: "Motion"               # Sensor type (informational)
    location: { x: 150.5, y: 80.2 } # Default map position (can be edited in UI)
    severity: "Medium"           # Default severity for alerts from this sensor
    associated_cameras:          # List of ASSOCIATED camera SANITIZED names
      - "Camera_North_Gate"      # Corresponds to "Camera North Gate"
      - "Camera_Overview_North"  # Corresponds to "Camera Overview North"
  - id: "GateContactWest"
    name: "מגען שער מערבי"
    type: "Contact"
    location: { x: 55.0, y: 210.0 }
    severity: "High"
    associated_cameras:
      - "Camera_West_Gate_Zoom"

# --- Sensor Input Configuration ---
sensor_input:
  enabled: true               # Set to true to enable sensor monitoring
  type: "logfile"             # Currently only 'logfile' is supported
  path: "sensor_alerts.log"   # Path to the log file written by the external system
                              # IMPORTANT: Ensure this process has read permissions!
  read_interval_ms: 1500      # How often to check the log file (milliseconds)

# --- SIEM Integration ---
siem:
  enabled: false              # Set to true to enable SIEM integration
  type: "Splunk"              # Options: Splunk, Elasticsearch
  api_url: "https://your-splunk-server:8089" # Base API URL (Splunk Management Port)
  auth_token: "ENV:SPLUNK_API_TOKEN" # API Token (Bearer or Splunk)
  # username: ""              # Optional: Username for Basic Auth (e.g., for Elastic)
  # password: ""              # Optional: Password for Basic Auth (use ENV:)
  verify_ssl: true            # Set to false ONLY for self-signed certs (SECURITY RISK)
  refresh_interval_min: 10    # Auto-refresh alerts interval (minutes, 0=disabled)
  # Splunk Specific:
  auth_header_type: "Bearer"  # Or "Splunk"
  splunk_query: 'search index=main earliest=-15m sourcetype=syslog "error" OR "failed" | head 100'
  # Elasticsearch Specific:
  elastic_index: "security-*" # Index pattern
  elastic_query_dsl: '{"size": 100, "query": {"bool": {"must": [{"range": {"@timestamp": {"gte": "now-15m/m"}}},{"query_string": {"query": "event.kind:alert OR error.message:* OR FAILED"}}]}}, "sort": [{"@timestamp": "desc"}]}'
  elastic_auth_method: "api_key" # Or "basic"

# --- SOAR Integration ---
soar:
  enabled: false              # Set to true to enable SOAR integration
  type: "SplunkSOAR"          # Options: SplunkSOAR, CortexXSOAR
  api_url: "https://your-soar-server" # Base API URL
  auth_token: "ENV:SOAR_API_TOKEN"    # API Token
  verify_ssl: true            # Set to false ONLY for self-signed certs (SECURITY RISK)
  # Cortex XSOAR Specific:
  # auth_header_name: "Authorization"
  # auth_value_prefix: "ApiKey "

# --- Map View Configuration ---
map_view:
  image_path: "map_background.png" # Optional path to map background image
  item_positions:                 # Stores positions for cameras and sensors
    # Camera positions (key is SANITIZED name)
    Camera_North_Gate: { x: 140.0, y: 60.5 }
    Camera_Overview_North: { x: 180.0, y: 100.0 }
    Camera_West_Gate_Zoom: { x: 40.0, y: 200.0 }
    # Sensor positions (key is sensor ID)
    FenceNorth01: { x: 150.5, y: 80.2 }
    GateContactWest: { x: 55.0, y: 210.0 }
    # Positions are automatically updated/added when moved in Edit Mode