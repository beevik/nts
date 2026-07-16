Release v0.3.1
==============

**Changes**

* Improve NTS error code handling by introducing more specific error
  responses.

**Fixes**

* Fixed a bug that could cause a panic if an invalid NTS extension field
  length was received.
* Perform memory alignment operations only on amd64 platforms.


Release v0.3.0
==============

**Changes**

* Added support for AES-GCM-SIV 128-bit encryption algorithm.
* Added support for chrony's compliant and noncompliant modes for AES-GCM-SIV.
* Added support for client-negotiated NTP server host and port requests.
* Added more meaningful error messages for NTS-KE failures.

**Fixes**

* Fixed a bug in the use of IPv6 with NTS server addresses.
* Fixed a bug in the way unrecognized record types were handled.
* Fixed a bug that could cause memory alignment errors on the Windows
  platform.

Release v0.2.1
==============

**Fixes**

* Fixed a bug that was causing some key exhanges to fail.

Release v0.2.0
==============

**Changes**

* Added new SessionOptions.

Release v0.1.1
==============

**Changes**

* Added support for custom SessionOptions.

**Fixes**

* Improvements to memory alignment for encryption.

Release v0.1.0
==============

**Changes**

* Initial pre-release.
