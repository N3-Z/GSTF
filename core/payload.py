import yaml
import os

# Fix #5: per-path cache so --payloads custom files use their own mapping.yaml
_mapping_cache = {}


def _get_mapping(payloads_path):
    """Load mapping.yaml from the same directory as the given payloads file."""
    mapping_path = os.path.join(
        os.path.dirname(os.path.abspath(payloads_path)), 'mapping.yaml'
    )
    if mapping_path not in _mapping_cache:
        _mapping_cache[mapping_path] = loadPayload(mapping_path)
    return _mapping_cache[mapping_path]


def loadPayload(path):
    with open(path) as file:
        return yaml.safe_load(file)


def getPayload(varType, payloads, payloads_path='./core/modules/payloads.yaml'):
    mapping = _get_mapping(payloads_path)
    return {
        attack: payloads['payload'][attack]
        for attack in mapping.get(varType, [])
        if payloads['payload'].get(attack)
    }


def combinePayload(data_item, payload_param):
    if isinstance(payload_param, str):
        return str(data_item) + payload_param
    if isinstance(payload_param, (int, float)):
        return payload_param
    return data_item  # Fix #3: fallback to original value instead of None
