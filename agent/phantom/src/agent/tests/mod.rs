mod construction;
mod metadata;
mod sleep;
mod transport;

use std::error::Error;
use std::io::{Read, Write};

pub(super) fn read_http_request(
    stream: &mut std::net::TcpStream,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    let mut header_end = None;
    let mut content_length = 0_usize;

    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);

        if header_end.is_none() {
            header_end =
                request.windows(4).position(|window| window == b"\r\n\r\n").map(|index| index + 4);
            if let Some(end) = header_end {
                let headers = std::str::from_utf8(&request[..end])?;
                content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length").then_some(value.trim())
                    })
                    .unwrap_or("0")
                    .parse::<usize>()?;
            }
        }

        if let Some(end) = header_end
            && request.len() >= end + content_length
        {
            break;
        }
    }

    let body = header_end.map_or_else(Vec::new, |end| request[end..].to_vec());
    Ok(body)
}

pub(super) fn write_http_response(
    stream: &mut std::net::TcpStream,
    body: &[u8],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    stream.write_all(
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())
            .as_bytes(),
    )?;
    stream.write_all(body)?;
    Ok(())
}

pub(super) fn encode_working_hours(
    start_hour: u32,
    start_minute: u32,
    end_hour: u32,
    end_minute: u32,
) -> i32 {
    ((1_u32 << 22)
        | ((start_hour & 0b01_1111) << 17)
        | ((start_minute & 0b11_1111) << 11)
        | ((end_hour & 0b01_1111) << 6)
        | (end_minute & 0b11_1111)) as i32
}

pub(super) fn local_time(hour: u8, minute: u8) -> time::OffsetDateTime {
    time::PrimitiveDateTime::new(
        time::Date::from_calendar_date(2026, time::Month::March, 23).unwrap_or(time::Date::MIN),
        time::Time::from_hms(hour, minute, 0).unwrap_or(time::Time::MIDNIGHT),
    )
    .assume_utc()
}
