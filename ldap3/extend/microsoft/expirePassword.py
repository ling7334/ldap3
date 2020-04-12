"""
"""


from ... import MODIFY_REPLACE, MODIFY_DELETE, MODIFY_ADD
from ...utils.log import log, log_enabled, PROTOCOL
from ...core.results import RESULT_SUCCESS
from ...utils.dn import safe_dn


def ad_expire_password(connection, user_dn, expire=True, controls=None):
    """
    :param connection: a bound Connection object
    :param user_dn: the user dn
    :param expire: a boolean where True means set the account password expired and False means present
    :param raise_error: If the operation fails it raises an error instead of returning False
    :return: a boolean where True means that the operation was successful and False means an error has happened
    Set the account password expired
    # Pwd-Last-Set attribute
    # The date and time that the password for this account was last changed.
    # This value is stored as a large integer that represents the number of 100 nanosecond intervals since January 1, 1601 (UTC).
    # If this value is set to 0 and the User-Account-Control attribute does not contain the UF_DONT_EXPIRE_PASSWD flag,
    # then the user must set the password at the next logon.
    # This attribute can only be set to 0 or -1.
    """
    if connection.check_names:
        user_dn = safe_dn(user_dn)

    if expire:
        result = connection.modify(user_dn,
                                   {'pwdLastSet': (MODIFY_REPLACE, [0])},
                                   controls)
    else:
        result = connection.modify(user_dn,
                                   {'pwdLastSet': (MODIFY_REPLACE, [-1])},
                                   controls)

    if not connection.strategy.sync:
        _, result = connection.get_response(result)
    else:
        result = connection.result

    # change successful, returns True
    if result['result'] == RESULT_SUCCESS:
        return True

    # change was not successful, raises exception if raise_exception = True in connection or returns the operation result, error code is in result['result']
    if connection.raise_exceptions:
        from ...core.exceptions import LDAPOperationResult
        if log_enabled(PROTOCOL):
            log(PROTOCOL, 'operation result <%s> for <%s>', result, connection)
        raise LDAPOperationResult(result=result['result'], description=result['description'], dn=result['dn'], message=result['message'], response_type=result['type'])

    return False