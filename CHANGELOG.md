CHANGELOG
=======

# XXXX.XX.XX


# 2020.10.10
- Minor internal updates to appease updated pylint/isort
- Add 3.9 to actions, update pins, try to behave like an adult :D
- Set preferred auth options at each authentication method to only try that explicit auth method
- Remove keepalive stuff for now (in line w/ scrapli core)
- Remove transport session locks


# 2020.07.04
- Disable ssh agent for now -- this will probably get supported/added in the future, but can cause hard to
 troubleshoot delays for now!
- Made transport timeout actually be used :)


# 2020.06.06
- First "real" release of scrapli_asyncssh -- still very early, but this has been working great in testing! Give it a
 shot!
