use std::io::{BufRead, Result as IoResult, Write};

// TODO add all responses from http://www.postfix.org/access.5.html
#[derive(Debug, PartialEq)]
pub enum PolicyResponse {
    Ok,
    Reject,
    RejectWithMessage(Vec<u8>),
    Defer,
    DeferWithMessage(Vec<u8>),
    Dunno,
}

pub trait PolicyRequestHandler<'l, T> {
    fn new(ctx: &'l T) -> Self;
    fn parse_line(&mut self, name: &[u8], value: &[u8]);

    fn response(self) -> PolicyResponse;
}

fn serialize_response(resp: PolicyResponse) -> Vec<u8> {
    match resp {
        PolicyResponse::Ok => b"OK".to_vec(),
        PolicyResponse::Reject => b"REJECT".to_vec(),
        PolicyResponse::RejectWithMessage(msg) => {
            let mut r = b"REJECT ".to_vec();
            r.extend_from_slice(&msg);
            r
        }
        PolicyResponse::Defer => b"DEFER".to_vec(),
        PolicyResponse::DeferWithMessage(msg) => {
            let mut r = b"DEFER ".to_vec();
            r.extend_from_slice(&msg);
            r
        }
        PolicyResponse::Dunno => b"DUNNO".to_vec(),
    }
}

#[test]
fn test_serialize_response() {
    assert_eq!(b"OK"[..], serialize_response(PolicyResponse::Ok)[..]);
    assert_eq!(b"REJECT"[..], serialize_response(PolicyResponse::Reject)[..]);
    assert_eq!(
        b"REJECT asdf"[..],
        serialize_response(PolicyResponse::RejectWithMessage(b"asdf".to_vec()))[..]
    );
    assert_eq!(b"DEFER"[..], serialize_response(PolicyResponse::Defer)[..]);
    assert_eq!(
        b"DEFER fdas"[..],
        serialize_response(PolicyResponse::DeferWithMessage(b"fdas".to_vec()))[..]
    );
    assert_eq!(b"DUNNO"[..], serialize_response(PolicyResponse::Dunno)[..]);
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
                return PolicyResponse::Reject;
            }
            PolicyResponse::DeferWithMessage(self.client_address.clone())
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
