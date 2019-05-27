use postfix_policy::{PolicyRequestHandler, PolicyResponse, handle_connection};
use std::string::String;
use std::os::unix::net::UnixListener;
use std::thread;
use std::io::{BufReader, Write, Error as IoError};
use std::fs::remove_file;
use std::io::stdout;

struct RequestDumper<'l> {
    connection_number: &'l usize,
    output: String,
}

impl<'l> PolicyRequestHandler<'l, usize, IoError> for RequestDumper<'l> {
    fn new(connection_number: &'l usize) -> Self { Self{
        connection_number: connection_number,
        output: String::new(),
    }}
    fn attribute(&mut self, name: &[u8], value: &[u8]) -> Option<IoError> {
        self.output.push_str(&format!("{}={}\n", String::from_utf8_lossy(name), String::from_utf8_lossy(value)));
        None
    }
    fn response(self) -> Result<PolicyResponse, IoError> {
        let stdout_mutex = stdout();
        let mut stdout = stdout_mutex.lock();
        writeln!(stdout, "Request on Connection #{}", self.connection_number)?;
        write!(stdout, "{}", self.output)?;
        writeln!(stdout, "End of Request on Connection #{}", self.connection_number)?;
        Ok(PolicyResponse::Dunno)
    }
}

fn main() {
    remove_file("/tmp/policy_example").ok();
    let listener = UnixListener::bind("/tmp/policy_example").expect("Binding listener socket failed");

    let mut connection_count: usize = 0;
    for client in listener.incoming() {
        let connection_number = connection_count;
        connection_count += 1;
        thread::spawn(move || {
            let client = client.expect("Something failed while listening");
            let mut sender = client.try_clone().expect("Could not clone client socket");
            let receiver = BufReader::new(client);
            handle_connection::<RequestDumper, _, _, _, _>(receiver, &mut sender, &connection_number).expect("handling connection failed");
        });
    }
}
