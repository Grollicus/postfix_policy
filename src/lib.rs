use std::io::{BufRead, Result as IoResult, Write};

#[derive(Debug, PartialEq)]
pub enum PolicyResponse {
    Ok,
    Reject(Vec<u8>),
    Defer(Vec<u8>),
    DeferIfReject(Vec<u8>),
    DeferIfPermit(Vec<u8>),
    Bcc(Vec<u8>),
    Discard(Vec<u8>),
    Dunno,
    Hold(Vec<u8>),
    Redirect(Vec<u8>),
    Info(Vec<u8>),
    Warn(Vec<u8>),
}

pub trait PolicyRequestHandler<'l, T> {
    fn new(ctx: &'l T) -> Self;
    fn parse_line(&mut self, name: &[u8], value: &[u8]);

    fn response(self) -> PolicyResponse;
}

fn serialize_response(resp: PolicyResponse) -> Vec<u8> {
    let mut message = Vec::new();
    let action: &[u8] = match resp {
        PolicyResponse::Ok => b"OK",
        PolicyResponse::Reject(msg) => {
            message = msg;
            b"REJECT"
        }
        PolicyResponse::Defer(msg) => {
            message = msg;
            b"DEFER"
        }
        PolicyResponse::DeferIfReject(msg) => {
            message = msg;
            b"DEFER_IF_REJECT"
        }
        PolicyResponse::DeferIfPermit(msg) => {
            message = msg;
            b"DEFER_IF_PERMIT"
        }
        PolicyResponse::Bcc(email) => {
            message = email;
            b"BCC"
        }
        PolicyResponse::Discard(msg) => {
            message = msg;
            b"DISCARD"
        }
        PolicyResponse::Dunno => b"DUNNO",
        PolicyResponse::Hold(msg) => {
            message = msg;
            b"HOLD"
        }
        PolicyResponse::Redirect(dst) => {
            message = dst;
            b"REDIRECT"
        }
        PolicyResponse::Info(msg) => {
            message = msg;
            b"INFO"
        }
        PolicyResponse::Warn(msg) => {
            message = msg;
            b"WARN"
        }
    };
    let mut resp = Vec::from(action);
    if message.len() != 0 {
        resp.push(b' ');
        resp.extend_from_slice(&message);
    }
    resp
}

#[test]
fn test_serialize_response() {
    assert_eq!(b"OK"[..], serialize_response(PolicyResponse::Ok)[..]);
    assert_eq!(
        b"REJECT"[..],
        serialize_response(PolicyResponse::Reject(Vec::new()))[..]
    );
    assert_eq!(
        b"REJECT asdf"[..],
        serialize_response(PolicyResponse::Reject(b"asdf".to_vec()))[..]
    );
    assert_eq!(b"DEFER"[..], serialize_response(PolicyResponse::Defer(Vec::new()))[..]);
    assert_eq!(
        b"DEFER fdas"[..],
        serialize_response(PolicyResponse::Defer(b"fdas".to_vec()))[..]
    );
    assert_eq!(
        b"DEFER_IF_REJECT"[..],
        serialize_response(PolicyResponse::DeferIfReject(Vec::new()))[..]
    );
    assert_eq!(
        b"DEFER_IF_REJECT blblblbl"[..],
        serialize_response(PolicyResponse::DeferIfReject(b"blblblbl".to_vec()))[..]
    );
    assert_eq!(
        b"DEFER_IF_PERMIT"[..],
        serialize_response(PolicyResponse::DeferIfPermit(Vec::new()))[..]
    );
    assert_eq!(
        b"DEFER_IF_PERMIT gsdk jf"[..],
        serialize_response(PolicyResponse::DeferIfPermit(b"gsdk jf".to_vec()))[..]
    );
    assert_eq!(
        b"BCC a@b.c"[..],
        serialize_response(PolicyResponse::Bcc(b"a@b.c".to_vec()))[..]
    );
    assert_eq!(
        b"DISCARD"[..],
        serialize_response(PolicyResponse::Discard(Vec::new()))[..]
    );
    assert_eq!(
        b"DISCARD asdffdas"[..],
        serialize_response(PolicyResponse::Discard(b"asdffdas".to_vec()))[..]
    );
    assert_eq!(b"DUNNO"[..], serialize_response(PolicyResponse::Dunno)[..]);
    assert_eq!(b"HOLD"[..], serialize_response(PolicyResponse::Hold(Vec::new()))[..]);
    assert_eq!(
        b"HOLD cmn,sd"[..],
        serialize_response(PolicyResponse::Hold(b"cmn,sd".to_vec()))[..]
    );
    assert_eq!(
        b"REDIRECT a@b.c"[..],
        serialize_response(PolicyResponse::Redirect(b"a@b.c".to_vec()))[..]
    );
    assert_eq!(
        b"INFO some message trololol"[..],
        serialize_response(PolicyResponse::Info(b"some message trololol".to_vec()))[..]
    );
    assert_eq!(
        b"WARN writing something to logs because logging is great and everyone should log everything"[..],
        serialize_response(PolicyResponse::Warn(
            b"writing something to logs because logging is great and everyone should log everything".to_vec()
        ))[..]
    );
}

pub fn handle_connection<'l, HandlerType, HandlerParamType, RS: BufRead, WS: Write>(
    mut reader: RS,
    writer: &mut WS,
    param: &'l HandlerParamType,
) -> IoResult<()>
where
    HandlerType: PolicyRequestHandler<'l, HandlerParamType>,
{
    let mut ctx: HandlerType = HandlerType::new(param);

    loop {
        let mut buf: Vec<u8> = vec![];
        if reader.read_until(b'\n', &mut buf)? == 0 {
            return Ok(());
        }

        if buf == b"\n" {
            let result = ctx.response();
            writer.write_all(b"action=")?;
            writer.write_all(&serialize_response(result))?;
            writer.write_all(b"\n\n")?;
            writer.flush()?;
            ctx = HandlerType::new(param);
            continue;
        }

        match buf.iter().position(|&c| c == b'=') {
            None => {
                println!("Read invalid line, cancelling connection: {:?}", buf);
                return Ok(());
            }
            Some(pos) => {
                let (left, mut right) = buf.split_at(pos);
                if right.len() < 2 {
                    println!("Read invalid line, cancelling connection: {:?}", buf);
                    return Ok(());
                }
                right = &right[1..right.len() - 1];
                ctx.parse_line(left, right);
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use super::{handle_connection, PolicyRequestHandler, PolicyResponse};
    use std::io::BufReader;
    use std::io::Cursor;

    struct DummyRequestHandler {
        found_request: bool,
        client_address: Vec<u8>,
    }
    impl<'l> PolicyRequestHandler<'l, ()> for DummyRequestHandler {
        fn new(_: &()) -> Self {
            Self {
                found_request: false,
                client_address: vec![],
            }
        }
        fn parse_line(&mut self, name: &[u8], value: &[u8]) {
            match name {
                b"request" => self.found_request = true,
                b"client_address" => self.client_address = value.to_vec(),
                _ => {}
            }
        }

        fn response(self) -> PolicyResponse {
            if !self.found_request {
                return PolicyResponse::Reject(Vec::new());
            }
            PolicyResponse::Defer(self.client_address.clone())
        }
    }

    #[test]
    fn test_handle_connection() {
        let mut input: Vec<u8> = vec![];
        input.extend_from_slice(b"request=smtpd_access_policy\n");
        input.extend_from_slice(b"protocol_state=RCPT\n");
        input.extend_from_slice(b"protocol_name=ESMTP\n");
        input.extend_from_slice(b"client_address=131.234.189.14\n\n");

        let reader = BufReader::new(Cursor::new(input));
        let mut output = Cursor::new(vec![]);
        handle_connection::<DummyRequestHandler, _, _, _>(reader, &mut output, &()).unwrap();
        assert_eq!(output.into_inner(), b"action=DEFER 131.234.189.14\n\n");
    }
}
