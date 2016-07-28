#![allow(dead_code, non_upper_case_globals, non_snake_case, non_camel_case_types)]

#[macro_use]
extern crate log;

mod ffi;

use std::ffi::{CString, CStr};
use std::error::Error;
use std::convert::From;
use std::collections::HashMap;

use std::default::Default;
use std::borrow::Cow;
use std::any::Any;

use std::os::raw;

pub static LDAP_SUCCESS: i32 = 0x00;
pub static LDAP_OPT_PROTOCOL_VERSION: i32 = 0x0011;

pub mod err {

    macro_rules! from {
        ($t: ty) => {
            impl ::std::convert::From<$t> for Error {
                fn from(e: $t) -> Self {
                    Error::Boxed(e.into())
                }
            }
        }
    }

    #[derive(Debug)]
    pub enum Error {
        Connecting(String),
        Generic(String),
        Boxed(Box<::std::error::Error + Send + Sync>)
    }

    impl Error {
        pub fn from_code(i: i32) -> Self {
            let msg = Self::decode(i);
            match i {
                -1 | -11 => Error::Connecting(msg),
                _ => Error::Generic(msg)
            }
        }

        fn decode(i: i32) -> String {
            unsafe {
                let msg = ::ffi::ldap_err2string(i as ::std::os::raw::c_int);
                ::std::ffi::CStr::from_ptr(msg).to_str()
                    .map(String::from)
                    .unwrap_or_else(|_| "Unknown exception".into())
            }
        }

    }

    impl ::std::error::Error for Error {
        fn description(&self) -> &str {
            match *self {
                Error::Connecting(ref msg) => { msg },
                Error::Generic(ref msg) => { msg },
                Error::Boxed(ref e) => { e.description() },
            }
        }
    }

    impl ::std::fmt::Display for Error {
        fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
            ::std::error::Error::description(self).fmt(f)
        }
    }

    pub type Result<T> = ::std::result::Result<T, Error>;    

    from!(::std::ffi::NulError);
    from!(&'static str);
}

#[derive(Debug)]
pub struct Connection { pub ptr: *mut ffi::LDAP }

impl Drop for Connection {
    fn drop(&mut self) {
        unsafe { ffi::ldap_destroy(self.ptr); }
    }
}

impl Connection {

    pub fn new() -> Self {
        Connection { ptr: ::std::ptr::null_mut() }
    }

    fn from_config(config: &Config) -> err::Result<Self> {
        let mut conn = Connection::new();
        if let Some(ref url) = config.url {
            conn = try!(conn.initialize(url));
        }
        for (k, v) in &config.options {
            conn = try!(conn.set_option(*k, v));
        }

        if let Some((ref dn, ref passwd)) = config.bind_args {
            conn = try!(conn.bind(dn, passwd));
        }        
        Ok(conn)
    }

    pub fn initialize(mut self, url: &str) -> err::Result<Self> {
        let url = try!(CString::new(url));
        let res = unsafe { ffi::ldap_initialize(&mut self.ptr, url.as_ptr()) };
        
        Self::result(res, self)
    }

    pub fn set_option<T: ?Sized>(mut self, key: i32, val: &T) -> err::Result<Self> {
        let res = unsafe {
            let key = key as raw::c_int;
            let val = val as *const _ as *const raw::c_void;
            ffi::ldap_set_option(self.ptr, key, val)
        };
        Self::result(res, self)
    }

    pub fn bind(mut self, dn: &str, passwd: &str) -> err::Result<Self> {

        let mut credentials = ffi::BerValue {
            bv_len: passwd.len() as ffi::ber_len_t,
            bv_val: try!(CString::new(passwd)).as_ptr() as *mut raw::c_char
        };

        let mechanism = ::std::ptr::null_mut();        
        let mut server_controls: *mut ffi::LDAPControl = ::std::ptr::null_mut();
        let mut client_controls: *mut ffi::LDAPControl = ::std::ptr::null_mut();
        let mut server_credentials: *mut ffi::BerValue = ::std::ptr::null_mut();

        let res = unsafe {
            ffi::ldap_sasl_bind_s(
                self.ptr, 
                try!(CString::new(dn)).as_ptr(), 
                mechanism,
                &mut credentials,
                &mut server_controls,
                &mut client_controls,
                &mut server_credentials)
        };
        Self::result(res, self)
    }

    pub fn search(&self, 
        base: &str, 
        scope: isize, 
        filter: &str) -> err::Result<EntrySet> {

        let mut msg: *mut ffi::LDAPMessage = ::std::ptr::null_mut();
        let mut server_controls: *mut ffi::LDAPControl = ::std::ptr::null_mut();
        let mut client_controls: *mut ffi::LDAPControl = ::std::ptr::null_mut();
        let timeout: *mut ffi::Struct_timeval = ::std::ptr::null_mut();
    
        let res = unsafe {
            ffi::ldap_search_ext_s(
                self.ptr, 
                try!(CString::new(base)).as_ptr(), 
                scope as raw::c_int, 
                try!(CString::new(filter)).as_ptr(), 
                ::std::ptr::null_mut() as *mut *mut raw::c_char, 
                0, 
                &mut server_controls, 
                &mut client_controls, 
                timeout, 
                0, 
                &mut msg)
        };

        Self::result(res, EntrySet { ptr: msg} )
    }

    fn result<T>(res: i32, val: T) -> err::Result<T> {
        if res == LDAP_SUCCESS {
            Ok(val)
        } else {
            Err(err::Error::from_code(res))
        }
    }
}

#[derive(Debug)]
pub struct EntrySet { pub ptr: *mut ffi::LDAPMessage }

impl Drop for EntrySet {
    fn drop(&mut self) {
        unsafe { ffi::ldap_msgfree(self.ptr); }
    }
}

impl EntrySet {

    pub fn entries<'a>(&self, conn: &'a Connection) -> EntriesIterator<'a> {
        EntriesIterator { curr: self.first_entry(conn), conn: conn }
    }

    pub fn first_entry(&self, conn: &Connection) -> Option<Entry> {
        let res = unsafe { ffi::ldap_first_entry(conn.ptr, self.ptr) };
        if res.is_null() { 
            None
        } else {
            Some(Entry { ptr: res })
        }   
    }

}

pub struct EntriesIterator<'a> {
    pub curr: Option<Entry>,
    pub conn: &'a Connection
}

impl<'a> Iterator for EntriesIterator<'a> {
    type Item = Entry;

    fn next(&mut self) -> Option<Self::Item> {
        let curr = self.curr.take();
        self.curr = curr.as_ref().and_then(|x| x.next_entry(self.conn));
        curr
    }
}

#[derive(Debug)]
pub struct Entry { pub ptr: *mut ffi::LDAPMessage }

impl Entry {

    pub fn dn(&self, conn: &Connection) -> Option<String> {
        unsafe { 
            let res = ffi::ldap_get_dn(conn.ptr, self.ptr);
            CStr::from_ptr(res).to_str().ok().map(String::from)
        }
    }

    pub fn values(&self, conn: &Connection, target: &str) -> Vec<String> {

        let mut out: Vec<String> = Vec::new();

        let target = match CString::new(target) {
            Ok(s) => { s },
            _ => { return out; }
        };    
    
        unsafe {
            let vals_x = ffi::ldap_get_values_len(conn.ptr, self.ptr, target.as_ptr());
            let len: usize = ffi::ldap_count_values_len(vals_x) as usize;
            let vals = ::std::slice::from_raw_parts(vals_x, len);

            for &val in vals {
                let val_x = (*val).bv_val as *const u8;
                let len = (*val).bv_len as usize;
                let val: &[u8] = ::std::slice::from_raw_parts(val_x, len);
                if let Ok(v) = ::std::str::from_utf8(val).map(String::from) {
                    out.push(v);
                }
            }
        }
        out
    }

    pub fn next_entry(&self, conn: &Connection) -> Option<Entry> {
        let res = unsafe { ffi::ldap_next_entry(conn.ptr, self.ptr) };        
        if res.is_null() { 
            None
        } else {
            Some(Entry { ptr: res })
        }
    }
}

unsafe impl Send for Connection {}

#[derive(Default, Debug, Clone)]
pub struct Config<'a> {
    pub url: Option<Cow<'a, str>>,
    pub bind_args: Option<(Cow<'a, str>, Cow<'a, str>)>,
    pub options: HashMap<i32, i32>
}

#[derive(Debug)]
pub struct Util<'a> {
    pub config: Config<'a>,
    pub connection: Connection
}

#[derive(Default, Debug)]
pub struct UtilBuilder<'a> { config: Config<'a> }

impl<'a> UtilBuilder<'a> {
    pub fn with_url(mut self, val: Cow<'a, str>) -> Self {
        self.config.url = Some(val);
        self
    }

    pub fn with_bind_args(mut self, dn: Cow<'a, str>, passwd: Cow<'a, str>) -> Self {
        self.config.bind_args = Some((dn, passwd));
        self
    }

    pub fn with_option(mut self, key: i32, val: i32) -> Self {
        self.config.options.insert(key, val);
        self
    }
    
    pub fn finish(self) -> err::Result<Util<'a>> {
        let connection = try!(Connection::from_config(&self.config));
        let out = Util {
            config: self.config,
            connection: connection
        };
        info!("Successfully created connection utility");
        Ok(out)
    }

}

impl<'a> Util<'a> {

    pub fn build() -> UtilBuilder<'a> { Default::default() }

    pub fn search(&mut self,
        base: &str, 
        scope: isize, 
        filter: &str) -> err::Result<EntrySet> {

        match self.connection.search(base, scope, filter) {
            Ok(entry_set) => { Ok(entry_set) },
            Err(err::Error::Connecting(_)) => {
                let new = try!(Connection::from_config(&self.config));
                info!("Connection error, trying again");
                ::std::mem::replace(&mut self.connection, new);
                self.search(base, scope, filter)
            },
            Err(e) => { Err(e) }
        }

    }
}

#[derive(Debug)]
pub struct Helper<'a> {
    pub util: Util<'a>,
    pub base: Cow<'a, str>
}

impl<'a> Helper<'a> {
    pub fn search(&mut self, filter: &str, fields: &[&str]) -> Vec<HashMap<String, Vec<String>>> {
        let mut out = Vec::new();
        let res = self.util.search(&self.base, 2, filter);
        for e in res.iter().flat_map(|x| x.entries(&self.util.connection) ) {
            let mut map = HashMap::new();
            for &field in fields {
                let val = e.values(&self.util.connection, field);
                map.insert(field.into(), val);
            }
            out.push(map);
        }
        out
    }

    pub fn authenticate(&self, dn: &str, passwd: &str) -> bool {
        let config = Config { 
            bind_args: None,
            ..self.util.config.clone()
        };
        Connection::from_config(&config)
            .into_iter()
            .map(|conn| conn.bind(dn, passwd).is_ok())
            .next()
            .unwrap_or_else(|| false)
    }

    pub fn find_and_authenticate(&mut self,
        filter: &str,
        fields: &[&str],
        passwd: &str) -> err::Result<HashMap<String, Vec<String>>> {

        if let Some(result) = self.util.search(&self.base, 2, filter)
            .iter()
            .flat_map(|x| x.entries(&self.util.connection) )
            .next() {
            if let Some(dn) = result.dn(&self.util.connection) {
                if self.authenticate(&dn, passwd) {
                    let mut map = HashMap::new();
                    for &field in fields {
                        let val = result.values(&self.util.connection, field);
                        map.insert(field.into(), val);
                    }
                    return Ok(map);
                }
            }
        }
        Err("Could not authenticate".into())
    }
}

#[cfg(test)]
mod tests {
    extern crate env_logger;

    use super::*;

    #[test]
    fn it_works() {
        env_logger::init().unwrap();
        let util = Util::build()
            .with_url(::std::env::var("LDAP_URL").unwrap().into())
            .with_bind_args(
                ::std::env::var("BIND_DN").unwrap().into(),
                ::std::env::var("BIND_PASSWD").unwrap().into())
            .with_option(LDAP_OPT_PROTOCOL_VERSION, 3)
            .finish()
            .expect("Couldn't build util");

        let mut helper = Helper {
            util: util,
            base: ::std::env::var("SEARCH_BASE").unwrap().into()
        };

        // let results = helper.search("(&(mail=j.h.brown@tcu.edu)(sn=Brown))", &["mail", "distinguishedName"]);
        // println!("{:?}", &results);

/*        println!("{:?}", helper.authenticate(
            &::std::env::var("DN").unwrap(),
            &::std::env::var("PASSWD").unwrap()));*/

        println!("{:?}", helper.find_and_authenticate(
            "(&(givenName=Jacob)(cn=jhbrown))",
            &["mail", "givenName", "sn"],
            "foo"));

        // let results = util.search(
        //     &::std::env::var("SEARCH_BASE").unwrap(),
        //     2,
        //     "(cn=jhbrown)");

        // let mut out = Vec::new();

        // for e in results.iter().flat_map(|x| x.entries(&util.connection) ) {
        //     let mut map = ::std::collections::HashMap::<String, Vec<String>>::new();
        //     for &field in ["mail", "sn", "givenName"].iter() {
        //         let val = e.values(&util.connection, field);
        //         map.insert(field.into(), val);
        //     }
        //     out.push(map);
        // }

        // println!("{:?}", &out);

        // let results = manager.search(
        //     &::std::env::var("SEARCH_BASE").unwrap(),
        //     2,
        //     "(cn=jhbrown)");

        // for e in results.iter().flat_map(|x| x.entries(manage.conn) ) {
        //     let mut map = HashMap::new();
        //     for &field in fields {
        //         let val = e.values(conn, field);
        //         map.insert(field.into(), val);
        //     }
        //     out.push(map);
        // }
        // out

        // let util = Util {
        //     url: ::std::env::var("LDAP_URL").unwrap().into(),
        //     bind_dn: ::std::env::var("BIND_DN").unwrap().into(),
        //     bind_passwd: ::std::env::var("BIND_PASSWD").unwrap().into(),
        //     base: ::std::env::var("SEARCH_BASE").unwrap().into()
        // };

        // let conn = util.conn().expect("NO CONNECTION");

        // let results = util.search(&conn, "(cn=jhbrown)", &["mail", "distinguishedName"]);

        // println!("{:?}", &results);

        // println!("{:?}", util.authenticate(
        //     &::std::env::var("DN").unwrap(),
        //     &::std::env::var("PASSWD").unwrap()));

        // println!("{:?}", util.find_and_authenticate(
        //     &conn, 
        //     "(cn=jhbrown)",
        //     &["mail", "givenname"],
        //     &::std::env::var("PASSWD").unwrap()));

        // println!("{:?}", util.find_and_authenticate(
        //     &conn, 
        //     "&(givenname=Jacob)(sn=Brown))",
        //     &["mail", "givenname"],
        //     "foo"));


    }
}
