# Hpfeeds Logger

A simple utility for logging hpfeeds events to files compatible with Splunk and ArcSight (coming soon).

## Installation

```
git clone https://github.com/Pwnlandia/mhn-logger.git
cd mhn-logger
virtualenv env
. env/bin/activate
pip install -r requirements.txt
```

## Configuration

Add an hpfeeds user that is capable of subscribing to all channels listed in your config. (see [add_user.py](https://github.com/Pwnlandia/hpfeeds/blob/master/broker/add_user.py) from Pwnlandia's fork of hpfeeds).

Create your config.

```
cp logger.json.example logger.json
vi logger.json
```

## Running

```
. env/bin/activate
./bin/hpfeeds-logger logger.json
```

## Notes

This application is designed to fail fast and should be run using supervisord or upstart configured to auto restart upon exitting.
