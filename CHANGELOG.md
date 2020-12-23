CHANGELOG
=======

# 2020.12.23
- Catch `ConnectionLost` exception during read operations so we can raise a scrapli exception instead of the asyncssh
 exception
- Explicitly pass ssh config file to asyncssh -- in this way if the user sets ssh_config_file=False we will make 
  sure that asyncssh ignores the config file
- Bumped up the default timeout values as they were probably a little on the aggressive side -- its user 
  configurable anyway so folks can set this to whatever they feel like!


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
