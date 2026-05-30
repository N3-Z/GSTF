import grpc
from google.protobuf.json_format import MessageToDict
from google.protobuf.descriptor import FieldDescriptor
import os
import ast
import subprocess
import sys
import importlib


_TYPE_MAP = {
    FieldDescriptor.TYPE_DOUBLE:   "double",
    FieldDescriptor.TYPE_FLOAT:    "double",
    FieldDescriptor.TYPE_INT64:    "int",
    FieldDescriptor.TYPE_UINT64:   "int",
    FieldDescriptor.TYPE_INT32:    "int",
    FieldDescriptor.TYPE_FIXED64:  "int",
    FieldDescriptor.TYPE_FIXED32:  "int",
    FieldDescriptor.TYPE_BOOL:     "bool",
    FieldDescriptor.TYPE_STRING:   "string",
    FieldDescriptor.TYPE_UINT32:   "int",
    FieldDescriptor.TYPE_SFIXED32: "int",
    FieldDescriptor.TYPE_SFIXED64: "int",
    FieldDescriptor.TYPE_SINT32:   "int",
    FieldDescriptor.TYPE_SINT64:   "int",
}

# Fix #4: resolve output path relative to this file, not CWD
_GRPC_CODE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'grpc_code')


def getDataResult(response):
    return MessageToDict(response)


def getStub(url, message_stub, secure, proxy=None):
    options = []

    if proxy:
        # Route gRPC traffic through HTTP CONNECT proxy (mitmproxy / Burp Suite)
        options.append(('grpc.enable_http_proxy', 1))
        os.environ['http_proxy']  = proxy
        os.environ['https_proxy'] = proxy
        os.environ['HTTP_PROXY']  = proxy
        os.environ['HTTPS_PROXY'] = proxy

    if secure:
        channel = grpc.aio.secure_channel(
            url, grpc.ssl_channel_credentials(), options=options
        )
    else:
        channel = grpc.aio.insecure_channel(url, options=options)

    return message_stub(channel)


def loadProto(path):
    abs_path    = os.path.abspath(path)
    include_dir = os.path.dirname(abs_path) or "."

    os.makedirs(_GRPC_CODE_DIR, exist_ok=True)

    # Fix #6: skip recompilation if generated file is already newer than proto
    base = os.path.splitext(os.path.basename(abs_path))[0]
    pb2  = os.path.join(_GRPC_CODE_DIR, f'{base}_pb2.py')
    if os.path.exists(pb2):
        try:
            if os.path.getmtime(pb2) >= os.path.getmtime(abs_path):
                return os.path.basename(abs_path)
        except OSError:
            pass

    subprocess.run([
        sys.executable, "-m", "grpc_tools.protoc",
        f"-I{include_dir}",
        f"--python_out={_GRPC_CODE_DIR}",
        f"--pyi_out={_GRPC_CODE_DIR}",
        f"--grpc_python_out={_GRPC_CODE_DIR}",
        abs_path,
    ], check=True)
    return os.path.basename(abs_path)


def import_proto_module(module_name):
    """Fix #7: import generated proto module, reloading if cached (picks up recompiled files)."""
    if _GRPC_CODE_DIR not in sys.path:
        sys.path.insert(0, _GRPC_CODE_DIR)
    if module_name in sys.modules:
        return importlib.reload(sys.modules[module_name])
    return importlib.import_module(module_name)


def get_request_class_name(filename):
    fullpath = os.path.join(_GRPC_CODE_DIR, f'{filename}.pyi')
    with open(fullpath) as file:
        node = ast.parse(file.read())
    return [n.name for n in node.body if isinstance(n, ast.ClassDef) and "Request" in n.name]


def get_all_class_stubs(filename):
    """Fix #2: return ALL ServiceStub class names (supports multi-service proto files)."""
    fullpath = os.path.join(_GRPC_CODE_DIR, f'{filename}.py')
    with open(fullpath) as file:
        node = ast.parse(file.read())
    stubs = [n.name for n in node.body if isinstance(n, ast.ClassDef) and "ServiceStub" in n.name]
    if not stubs:
        raise ValueError(f"No ServiceStub class found in {filename}.py")
    return stubs


def get_service_methods(gs_service_module):
    """Return [{method_name, input_type, service_name, stub}] from the protobuf DESCRIPTOR.

    Replaces the fragile convention of stripping 'Request' from a message class name to
    guess the RPC name. Reads actual RPC definitions, so it works for any naming scheme
    (e.g. GetSession(TokenAuthorizationRequest))."""
    methods = []
    for svc_name, svc_desc in gs_service_module.DESCRIPTOR.services_by_name.items():
        for method in svc_desc.methods:
            methods.append({
                'method_name':  method.name,
                'input_type':   method.input_type.name,
                'service_name': svc_name,
                'stub':         None,
            })
    return methods


def get_request_variable_names(request_type):
    return [field.name for field in request_type.DESCRIPTOR.fields]


def get_request_variable_type(field_descriptor):
    return _TYPE_MAP.get(field_descriptor.type)


def generate_data(data_type):
    defaults = {"int": 1, "string": "test", "bool": False, "double": 1.0}
    return defaults.get(data_type, '')
