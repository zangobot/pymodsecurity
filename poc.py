from ModSecurity import ModSecurity
from ModSecurity import Rules
from ModSecurity import Transaction
from ModSecurity import LogProperty

import re


class MatchedRule:
    def __init__(self, rule_message):
        self.rule_id = rule_message.m_ruleId
        self.severity = rule_message.m_severity
        self.tags = rule_message.m_tags



class RulesLogger:
    def __init__(self, regex_rules_filter=None, debug=False):
        self._rules_triggered = []
        self._debug = debug
        self._rules_filter = re.compile(regex_rules_filter) if regex_rules_filter is not None \
                                else re.compile('^.*')
        self._score = 0

    def __call__(self, data, rule_message):
        if self._debug:
            print("-- RULE MESSAGE --")
            print(rule_message.m_tags)
            print('[DEBUG] ModSecurity rule logger callback')
            print("[DEBUG] ID: {}, Message: {}, Phase: {}, Severity: {}".format(
                rule_message.m_ruleId, rule_message.m_message, rule_message.m_phase,
                rule_message.m_severity))

        if rule_message.m_ruleId == 949110:
            self._score = float(re.findall(r"\(Total Score: (\d+)\)", str(rule_message.m_message))[0])
        if re.match(self._rules_filter, str(rule_message.m_ruleId)) and str(rule_message.m_ruleId) not in self._rules_triggered:
            self._rules_triggered.append(MatchedRule(rule_message))

    def get_rules(self):
        return self._rules_triggered

    def get_score(self):
        return self._score

modsec = ModSecurity()
print(modsec.whoAmI())

rules = Rules()
rules.loadFromUri("REQUEST-901-INITIALIZATION.conf")
rules.loadFromUri("REQUEST-942-APPLICATION-ATTACK-SQLI.conf")
rules.loadFromUri("REQUEST-949-BLOCKING-EVALUATION.conf")

rules_logger_cb = RulesLogger()
modsec.setServerLogCb2(rules_logger_cb, LogProperty.RuleMessageLogProperty)

transaction = Transaction(modsec, rules)
transaction.processURI("http://www.modsecurity.org/test?pass=admin%22%20OR%201=1--%20-", "GET", "2.0")
transaction.processRequestHeaders()
transaction.processRequestBody()


print({ r.rule_id: r.severity for r in rules_logger_cb.get_rules() if 'paranoia-level/2' in r.tags})
print([tag for r in rules_logger_cb.get_rules() for tag in r.tags])
print(sum(r.severity for r in rules_logger_cb.get_rules() if 'paranoia-level/2' in r.tags))
