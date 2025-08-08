import pickle
import base64
from pathlib import Path
import subprocess

from flask import Blueprint, request, jsonify, session

bp = Blueprint("actions", __name__)


@bp.route("/message", methods=["POST"])
def log_entry():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"})
    access_level = user_info[2]
    if access_level > 2:
        return jsonify({"error": "access level < 2 is required for this action"})
    filename_param = request.form.get("filename")
    if filename_param is None:
        return jsonify({"error": "filename parameter is required"})
    text_param = request.form.get("text")
    if text_param is None:
        return jsonify({"error": "text parameter is required"})

    user_id = user_info[0]
    user_dir = "data/" + str(user_id)
    user_dir_path = Path(user_dir)
    if not user_dir_path.exists():
        user_dir_path.mkdir()

    filename = filename_param + ".txt"
    path = Path(user_dir + "/" + filename)
    with path.open("w", encoding="utf-8") as open_file:
        # vulnerability: Directory Traversal
        open_file.write(text_param)
    return jsonify({"success": True})


@bp.route("/grep_processes")
def grep_processes():
# Setup logger for security monitoring
logger = logging.getLogger(__name__)

# Setup rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

def is_safe_input(input_str):
    """Validate input against allowlist pattern"""
    return bool(re.match(r'^[a-zA-Z0-9_\-]+$', input_str))

def validate_input(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        name = request.args.get("name")
        # Sanitize input using bleach
        sanitized_name = clean(name) if name else ""
        
        # Log the access attempt
        logger.info(f"Process search requested for: {sanitized_name}")
        
        if not name or not isinstance(name, str) or not is_safe_input(name):
            return jsonify({"error": "invalid parameter"})
        return func(*args, **kwargs)
    return wrapper

@limiter.limit("10 per minute")
@validate_input
def grep_processes():
    name = request.args.get("name")
    # Input already validated by decorator
    
    # Fixed: Avoiding shell=True and using array arguments
    res = subprocess.run(
        ["ps", "aux"], 
        capture_output=True, 
        text=True,
        shell=False
    )
    
    # Filter results in Python rather than using grep/awk with shell=True
    if res.stdout:
        lines = res.stdout.splitlines()
        matching_processes = [line.split()[10] if len(line.split()) > 10 else "" 
                             for line in lines if name in line]
        return jsonify({"success": True, "names": matching_processes})
    
    return jsonify({"error": "no stdout returned"})

def deserialized_descr():
    pickled = request.form.get('pickled')
    data = base64.urlsafe_b64decode(pickled)
    # vulnerability: Insecure Deserialization
    deserialized = pickle.loads(data)
    return jsonify({"success": True, "description": str(deserialized)})
