# Script to update a pre-1.0.4 OpenLI provisioner config to match the
# format required post-1.0.4.

# Requires: python3, pyyaml (can be installed by running: pip3 install pyyaml)
#
# Usage: python3 update-provconf-1.0.4.py <oldprovconfigfile> <newinterceptconfigfile>
#
# Please use full paths when specifying the file location arguments.
#
# NOTE: your original provisioner config file will be modified by this
# script -- the intercept config from the old provisioner config will be
# removed and moved to the new intercept config file.
# In case something goes wrong, a backup will be made of your old provisioner
# configuration (written to <oldprovconfigfile--bkup>).
#
# NOTE: any comments in your original config file will NOT be preserved. If
# these are important to you, please update your config according to the
# manual process ( https://github.com/OpenLI-NZ/openli/wiki/Upgrading-to-1.0.4 ).

import yaml, sys, string

# Check we have all the necessary arguments
if len(sys.argv) < 3:
        print("Usage: %s oldprovconfig newprovconfig" % (sys.argv[0]))
        sys.exit(-1)

# Read from oldprovconfig, split into two files.
# Intercept-related config goes into the newprovconfig file.
# Other config goes back into the original provconfig file.
try:
        inp = open(sys.argv[1], "r")
except:
        print("Unable to open old provisioner config file %s" % (sys.argv[1]))
        raise
try:
        outp = open(sys.argv[2], "w")
except:
        print("Unable to open new provisioner config file %s" % (sys.argv[2]))
        raise

try:
        backup = open(sys.argv[1] + "--bkup", "w")
except:
        print("Unable to open backup provisioner config file %s" % (sys.argv[1] + "--bkup"))
        raise

# pyyaml does all the hard work for us -- this turns the existing YAML
# config into a dict
oldyaml = yaml.load(inp, Loader=yaml.FullLoader)

inp.close()

# Write out our backup file, just in case we mess up somehow
# NOTE: comments will be lost.
yaml.dump(oldyaml, backup)
backup.close()

# Split the original config into "intercept related" and "not"
newobj = {}
oldobj = {}

for k,v in oldyaml.items():
        if k in ['sipservers', 'radiusservers', 'ipintercepts', \
                        'voipintercepts', 'agencies']:
                newobj[k] = oldyaml[k]
        else:
                oldobj[k] = oldyaml[k]

# Write out the new intercept config file
yaml.dump(newobj, outp)

# Add the "intercept-config-file" option to the provisioner config, so that
# everything will just work afterwards.
oldobj['intercept-config-file'] = sys.argv[2]

# Overwrite the original config with the new "intercept-less" version.
try:
        replacep = open(sys.argv[1], "w")
except:
        print("Unable to open old provisioner config file for replacement %s" % (sys.argv[2]))
        raise

yaml.dump(oldobj, replacep)

outp.close()
