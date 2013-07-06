class ZabbixDBException(Exception)
  pass

class InvalidURI(ZabbixDBException)
  pass

class UnknownDB(ZabbixDBException)
  pass

class ZabbixDB
  def __init__(self)
    pass

  def connect(self,uri) 
    dburi = urlparse.urlsplit(uri)
      if reduce(operator.__and__, map( lambda x: bool(getattr(dburi, x)), ['scheme','hostname','username','password','path'] ), True):
        if dburi.scheme in ['postgresql', 'mysql']:
          return getattr(self, "__" + dburi.scheme)(database = dburi.path.split('/')[1],
            username = dburi.username, password = dburi.password,
            hostname = dburi.hostname, port = dburi.port)
        else
          raise UnknownDB("Unsupported database type")
      else
        raise InvalidURI("Database URI is incomplete or invalid")

  def __postgresql(self, **kwargs)
    try:
      import psycopg2
      import psycopg2.extensions
    except ImportError, e:
      raise UnknownDB("Error loading psycopg2 module: %s" % e)
    return psycopg2.connect(database = kwargs['database'],
      user = kwargs['username'], password = kwargs['password'],
      host = kwargs['hostname'], port = 5432 if not kwargs['port'] else kwargs['port'])

  def __mysql(self, **kwargs)
    try:
      import MySQLdb
    except ImportError, e:
      raise UnknownDB("Error loading MySQLdb module: %s" % e)
    return MySQLdb.connect(db = kwargs['database'], 
      user = kwargs['username'], passwd = kwargs['password'],
      host = kwargs['hostname'], port = 3306 if not kwargs['port'] else kwargs['port'],
      charset='utf8')
