use elfparse;

use std::{env, error::Error, fs};

fn main() -> Result<(), Box<dyn Error>> {
    let input_path = env::args().nth(1).expect("usage: info FILE");
    let input = fs::read(&input_path)?;

    let elf = match elfparse::File::parse_or_print_error(&input[..]) {
        Ok(bin) => bin,
        Err(e) => {
            eprintln!("input is not a supported ELF file!");
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    println!("Binary: {}", input_path);
    println!("Machine Type: {:?}", elf.machine);
    println!("Binary Type: {:?}", elf.r#type);
    println!("Entry Point: {:?}", elf.entry_point);

    println!("Program Headers:");
    for pheader in elf.program_headers {
        println!("{:?}", pheader);
    }

    println!("Section Headers:");

    Ok(())
}
