from .permissions import resource_access

WRITE_PERMISSIONS = {"vm.write", "resource.write"}


def review_write_access(resource_name, data_dir):
    data = resource_access(resource_name, data_dir)

    writers = []
    direct_users = set()
    group_users = set()

    for principal in data["principals"]:
        if not principal["principal_id"].startswith("u-"):
            continue

        if WRITE_PERMISSIONS.intersection(principal["capabilities"]):
            writers.append(principal["principal_id"])
            for grant in principal["grant_evidence"]:
                if not WRITE_PERMISSIONS.intersection(grant["capabilities"]):
                    continue

                if len(grant["membership_chain"]) == 1:
                    direct_users.add(principal["principal_id"])
                else:
                    group_users.add(principal["principal_id"])
    return {
        "direct_users": sorted(direct_users),
        "group_users": sorted(group_users)
    }