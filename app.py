from http.client import HTTPException

from flask import Flask, render_template_string, request, Response
import logging
import dns.resolver
import re
from enum import Enum
import traceback
import redis
import time


app = Flask(__name__)
# This cache is put in place to avoid re-computing the policy as much as possible at the policy server end. Do
# not confuse it with policy caching as in RFC 8461. It's for policy server's own purpose. Also, if it's not there
# max_age keeps going down at every fetch since it's computed from TTL of DNS records
r = redis.StrictRedis(host='localhost', port=6379, db=0, decode_responses=True)
logging.basicConfig(filename='access.log', filemode='a', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.DEBUG)
logger = logging.getLogger(__name__)
POLICY_HOSTING_PROVIDER = "p.com"
EXAMPLE_POLICY_DOMAIN = "a.com"
EMAIL_HOSTING_PROVIDER = "ehp.com"
POLICY_SERVER_IP = "1.2.3.4"


class ModeType(Enum):
    enforce = 3
    testing = 2
    none = 1


def _get_desired_mode(name):
    """
    Get the desired mode for the domain owner via a form
    """
    return


def _add_sts_deleg_txt_record(name, mode):
    """
    Create a new STS Delegate TXT record under "mta-sts." + name + ".sts-deleg." + POLICY_HOSTING_PROVIDER with a value
     "v=STSv1; id=1; set_mode=" + mode
    """
    pass


def _point_to_policy_server_ip(name):
    """
    Point the "mta-sts." + name + ".sts-deleg." + POLICY_HOSTING_PROVIDER to the POLICY_SERVER_IP
    """
    pass


def _get_a_tls_certificate(name):
    """
    Get a TLS certificate for 'mta-sts.' + name.
    This should be easily doable either by expanding the current cert or getting a new cert completely
    (since the server supports SNI) if proper CNAME records are there already.
    """
    pass


def _fetch_mx_records(name):
    mxs = []
    try:
        # Query MX records
        answers = dns.resolver.resolve(name, 'MX')
        # Print each MX record
        for rdata in answers:
            logging.debug(f"Mail server: {rdata.exchange}, Priority: {rdata.preference}")
            mxs.append(rdata.exchange.to_text()[:-1])
    except dns.resolver.NoAnswer:
        logging.debug("No MX records found for " + name)
        return []
    except dns.resolver.NXDOMAIN:
        logging.debug("Domain " + name + " does not exist")
        return []
    except Exception as e:
        logging.debug(f"An error occurred: {e}" + " while trying to fetch MX records for " + name)
        return []
    return mxs


def _validate_mode_tls_syntax(txt):
    fields = list(map(lambda s: s.strip(' \t'), re.split('[ \t]*;[ \t]*', txt)))
    if fields[0] != 'v=TLSMDv1':
        # already covered before but checking it again anyway
        return False
    is_mode_present = False
    for field in fields[1:]:
        if not field:
            continue
        elif field.startswith('mode='):
            modeValue = field[5:]
            # wrong mode
            if modeValue not in {'enforce', 'testing', 'none'}:
                logging.debug(f"invalid mode found {txt}")
                return False
            is_mode_present = True
        else:
            # invalid extension
            if not re.match('^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}=[\x21-\x3a\x3c\x3e-\x7e]{1,}$', field):
                logging.debug(f"invalid extension found {field} {txt}")
                return False
    # no mode found
    if not is_mode_present:
        logging.debug(f"no mode found {txt}")
        return False
    return True


def _get_mode(txt):
    fields = list(map(lambda s: s.strip(' \t'), re.split('[ \t]*;[ \t]*', txt)))
    for field in fields[1:]:
        if field.startswith('mode='):
            modeValue = field[5:]
            return modeValue
    return


def _fetch_mode_tls_records(mx):
    try:
        records = []
        # Query TXT records
        answers = dns.resolver.resolve("mode._tls." + mx, 'TXT')
        # Print each MX record
        for rdata in answers:
            logging.debug(f"TXT Record: {rdata}")
            txt = b''.join(rdata.strings).decode('ascii')
            # records that do not begin with v=TLSMDv1; are discarded
            if not txt.startswith("v=TLSMDv1;"):
                continue
            records.append(txt)
        if len(records) > 1:
            logging.error(f"More than one mode._tls TXT record is found for {mx}")
            return None, None, None
        if len(records) == 0:
            logging.error(f"No mode._tls TXT record is found for {mx}")
            return None, None, None
        if len(records) == 1:
            logging.debug(f"Got 1 mode._tls TXT record in {records[0]}")
            if _validate_mode_tls_syntax(records[0]):
                mode = _get_mode(records[0])
                return records[0], answers.rrset.ttl, mode
            else:
                return None, None, None
    except dns.resolver.NoAnswer:
        logging.debug("No TXT records found for " + mx)
        return None, None, None
    except dns.resolver.NXDOMAIN:
        logging.debug("Domain " + mx + " does not exist")
        return None, None, None
    except Exception as e:
        logging.debug(f"An error occurred: {str(e)} while trying to fetch TXT records for {mx}")
        logging.debug(traceback.format_exc())
        return None, None, None


def _check_extension_fields(fields):
    for field in fields:
        if not field:
            continue
        if not re.match('^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}=[\x21-\x3a\x3c\x3e-\x7e]{1,}$', field):
            return
        if field.startswith('set_mode='):
            return field[9:]
    return 'none'


def _fetch_mta_sts_desired_mode(name):
    try:
        # Query TXT records
        answers = dns.resolver.resolve('_mta-sts.' + name + '.sts-deleg.' + POLICY_HOSTING_PROVIDER, 'TXT')
        mta_sts_records = []
        for record in answers:
            if len(record.strings) < 1:
                # This is actually possible, though I don't know whether it is allowed.
                continue
            data = b''.join(record.strings).decode('ascii')
            if data.startswith("v=STSv1;"):
                mta_sts_records.append(data)
        if len(mta_sts_records) > 1:
            # TODO provide these results
            logging.debug('Multiple MTA-STS TXT records found for ' + name)
            return
        if len(mta_sts_records) == 0:
            logging.debug('No MTA-STS TXT record found for ' + name)
            return
        fields = list(map(lambda s: s.strip(' \t'), re.split('[ \t]*;[ \t]*', mta_sts_records[0])))
        return _check_extension_fields(fields[1:])
    except dns.resolver.NoAnswer:
        logging.debug("No MTA-STS TXT records found for " + name)
        return
    except dns.resolver.NXDOMAIN:
        logging.debug("Domain " + name + " does not exist")
        return
    except Exception as e:
        logging.debug(f"An error occurred: {e}" + " while trying to fetch MTA-STS TXT records for " + name)
        return


def _set_value(key, value):
    r.set(key, value)


def _get_value(key):
    value = r.get(key)
    if value:
        return value
    return


def _publish_policy_with_none(name):
    """
    1. Update the policy of name with mode changed to 'none' and a max_age = 86400
    2. Update cache
    """
    pass


def _update_txt_record(name):
    """
    Update id of TXT record of 'mta-sts.' + name + '.sts-deleg.' + POLICY_PROVIDER to trigger the fetch of new policy
    """
    pass


def _check_presence_of_cname_records(name: str) -> bool:
    """
    Checks if the '_mta-sts.' + name and 'mta-sts.' + name points to '.sts-deleg.' + POLICY_PROVIDER domains
    """
    pass


def _parse_policy(text):
    lines = text.splitlines()
    res = dict()
    res['mx'] = list()
    for line in lines:
        line = line.rstrip()
        key, _, value = line.partition(':')
        value = value.lstrip()
        if key == 'mx':
            res['mx'].append(value)
        else:
            res[key] = value
    return res


def _match_policy_v2(candidate, policyNames):
    candidate = candidate.lower()
    if policyNames is None:
        return False
    for mx in policyNames:
        mx = mx.lower()
        if mx == candidate:
            return True
        # Wildcard matches only the leftmost label.
        # Wildcards must always be followed by a '.'.
        if mx[0] == '*':
            parts = candidate.split('.', 1) # Split on the first '.'.
            if len(parts) > 1 and parts[1] == mx[2:]:
                return True
    return False


def _validate(name):
    if not _check_presence_of_cname_records(name):
        return False
    policy = serve_policy().data
    mxs = _fetch_mx_records(name)
    policy_dict = _parse_policy(policy)
    if not mxs:
        return False
    for mx in mxs:
        try:
            if _match_policy_v2(mx, policy_dict['mx']):
                return True
        except Exception as e:
            continue
    return False


@app.route('/remove/<name>')
def remove_policy_and_txt_record(name):
    """
    Remove the mta-sts DNS records related to name
    """
    pass


@app.route("/delegation/<name>")
def delegation_agreement(name):
    # This API is called at the successful completion of the out-of-band mechanism
    # At the end of the out-the-band mechanism, the domain owner should have the following records set:
    # _mta-sts.<domain> CNAME _mta-sts.<domain>.sts-deleg.<policy_provider>
    # mta-sts.<domain> CNAME mta-sts.<domain>.sts-deleg.<policy_provider>
    mode = _get_desired_mode(name)
    _add_sts_deleg_txt_record(name, mode)
    _point_to_policy_server_ip(name)
    _get_a_tls_certificate(name)


@app.route("/opt_out/<name>")
def opt_out_agreement(name):
    _publish_policy_with_none(name)
    _update_txt_record(name)
    # After 604800 seconds, using a cron job call the following API
    # The ideal rule is to remove the TXT and policy endpoint once all the previously cached policies have expired.
    # Since the largest TTL possible is 604800s, which is going to be the highest possible max_age from our server,
    # we can remove records safely after this period
    remove_policy_and_txt_record(name)  # async


@app.route("/.well-known/mta-sts.txt")
def serve_policy():
    logging.info("serving policy file")
    try:
        host = request.headers.get('Host')
        logging.debug("requesting policy from " + host)
        if host.startswith('mta-sts.') and host.endswith('.sts-deleg.p.com'):
            name = host.split('mta-sts.')[1].split('.sts-deleg.p.com')[0]
            logging.debug("requesting policy for " + name)
        elif host.startswith('mta-sts.') and not host.endswith('.sts-deleg.p.com'):
            name = host.split('mta-sts.')[1]
            logging.debug("requesting policy for " + name)
        else:
            return render_template_string('''
                <html>
                <head><title>Policy domain not found</title></head>
                </html>
            ''')
        # check whether the policy is in the cache
        if _get_value(name + '_policy'):
            policy = _get_value(name + '_policy')
            max_age = float(_get_value(name + '_max_age'))
            cached_when = float(_get_value(name + '_cached_when'))
            if time.time() > max_age + cached_when:
                logging.debug(f'evicted from cache {name}')
                r.delete(name)
            else:
                logging.debug(f'serving from cache {name}')
                return Response(policy, mimetype='text/plain')
        mxs = _fetch_mx_records(name)
        # we should also have the option to upload mx patterns for the users to support wildcard entries; right now, it can be omitted
        # mx_patterns = get_uploaded_mx_patterns()
        policy = "version: STSv1\n"
        mx_entries = []
        min_ttl = 604800
        min_mode = 3
        for mx in mxs:
            txt, ttl, mode = _fetch_mode_tls_records(mx)
            if not txt:
                # note: when mode._tls is partially available, add only the valid ones in mx entries
                continue
            logging.debug(f"In validation: {txt} {ttl} {mode}")
            min_ttl = min(min_ttl, ttl)
            mx_entries.append(mx)
            min_mode = min(ModeType[mode].value, min_mode)
        for mx in mx_entries:
            policy += "mx: " + mx + "\n"
        policy += "max_age: " + str(min_ttl) + "\n"
        mode = _fetch_mta_sts_desired_mode(name)
        if mode is None:
            logging.debug(f"There is an error with {name}'s MTA-STS TXT record")
            raise HTTPException(status_code=404, detail="")
        min_mode = min(ModeType[mode].value, min_mode)
        policy += "mode: " + ModeType(min_mode).name + "\n"
        _set_value(name + '_policy', policy)
        _set_value(name + '_max_age', min_ttl)
        _set_value(name + '_cached_when', time.time())
        logging.debug(f"Pushed to redis {name}")
        return Response(policy, mimetype='text/plain')
    except Exception as e:
        logging.debug("In policy serving: " + str(e))
        logging.debug(traceback.format_exc())
        return render_template_string('''
            <html>
                <head><title>Error!!!</title></head>
                <body>
                <h1>Error!!!</h1>
                </body>
            </html>
        ''')


@app.route("/validate/<name>/<rem_time>")
def validate(name, rem_time):  # async
    # this is the periodical validation API; rem_time indicates remaining time before max_age expiry
    # for every policy domain in the cache, call this API in an inverse exponential backoff fashion with respect to the max_age
    validation_result = _validate(name)
    if not validation_result and rem_time <= 300:
        # update the policy mode to 'testing'
        # save new policy to cache
        # serve new policy
        pass
    elif not validation_result:
        # false but we still have some time to revalidate
        # call this API after 1/2 of rem_time again
        validate(name, rem_time/2)  # async
    else:
        # no need to do anything; stop calling the API for this domain in this cache cycle
        pass
    return


@app.route('/')
def index():  # put application's code here
    app.logger.info("In index")
    return render_template_string('''
        <html>
        <head><title>p.com</title></head>
        <body>
            <h1>We host MTA-STS policy file for free!</h1>
            <p>If you want to use our service, please email us mentioning your domain at TBD.</p>
            <p>We'd give you a DNS challenge to ensure whether you control the domain and if verified, will give you 
            some DNS records that will activate our service.</p>
            <p>We plan to integrate the Domain Connect protocol later on to automate these steps.</p>
        </body>
        </html>
    ''')


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)