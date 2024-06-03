# Report Writing

## Executive Summary Notes

Bare Minimum Information MUST contain:

```
Executive Summary:
- Scope: https://kali.org/login.php
- Timeframe: Jan 3 - 5, 2022
- OWASP/PCI Testing methodology was used
- Social engineering and DoS testing were not in scope
- No testing accounts were given; testing was black box from an external IP address
- All tests were run from 192.168.1.2
```

## Construct the Executive Summery

* Describing the Engagement
* Identifying the Positives
* Explaining a vulnerability
* Concise conclusion

Positive Outcome: "There were no limitations or extenuating circumstances in the engagement. The time allocated was sufficient to thoroughly test the environment."

Neutral Outcome: "There were no credentials allocated to the tester in the first two days of the test. However, the attack surface was much smaller than anticipated. Therefore, this did not have an impact on the overall test. OffSec recommends that communication of credentials occurs immediately before the engagement begins for future contracts, so that we can provide as much testing as possible within the allotted time."

Negative Outcome: "There was not enough time allocated to this engagement to conduct a thorough review of the application, and the scope became much larger than expected. It is recommended that more time is allocated to future engagements to provide more comprehensive coverage."

## Technical Summery Report Notes

Common areas for the technical summary should be

* User and Privilege Management
* Architecture
* Authorization
* Patch Management
* Integrity and Signatures
* Authentication
* Access Control
* Audit, Log Management and Monitoring
* Traffic and Data Encryption
* Security Misconfigurations

## Technical Findings and Recommendations

* Documented in tabular form and provide  background if necessary
* Explain in story format exactly what happened (attack narrative)
* Full details should be in document in the appendix
* Remediation advice should be clear and consice and practical
* Each presented step should be its own solution.
* Docucument in detail where the application is affected and how the vulnerability can be exploited
* Use Screenshot plus caption and description in the text of what we see
