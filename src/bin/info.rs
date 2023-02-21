use elfparse;

use std::{env, error::Error, fs};

fn main() -> Result<(), Box<dyn Error>> {
    let input_path = env::args().nth(1).expect("usage: info FILE");
    let input = fs::read(&input_path)?;

    let elf = match elfparse::File::parse(&input[..]) {
        Ok((_, bin)) => bin,
        Err(_) => {
            eprintln!("input is not a suppoorted ELF file!");
            std::process::exit(1);
        }
    };

    // add better elf output - debug for now
    println!("{:?}", elf);

    Ok(())
}
