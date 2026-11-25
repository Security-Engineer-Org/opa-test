
package authz

import rego.v1

test_admin_access if {
    allow with input as {
        "user": {"id": "A1", "role": "admin"},
        "action": "delete",
        "resource": {"type": "document"}
    }
}

test_employee_read if {
    allow with input as {
        "user": {"id": "E1", "role": "employee"},
        "action": "read",
        "resource": {
            "type": "document",
            "owner": "E1",
            "classification": "internal"
        }
    }
}

test_employee_update_denied if {
    not allow with input as {
        "user": {"id": "E1", "role": "employee"},
        "action": "update",
        "resource": {"type": "document", "owner": "E1"}
    }
}

test_confidential_access_denied if {
    not authorized with input as {
        "user": {"id": "E1", "role": "employee"},
        "action": "read",
        "resource": {
            "type": "document",
            "owner": "E1",
            "classification": "confidential"
        }
    }
}
