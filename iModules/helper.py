import yaml

def loadYML(infile):
  with open(infile,'r') as stream:
    try:
      data = yaml.safe_load(stream)
    except yaml.YAMLError as exc:
      print(exc)
  return data

# Global 
CONFIG   = loadYML('config.yml')
