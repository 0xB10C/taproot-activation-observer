use std::collections::hash_map::HashMap;
use std::convert::TryInto;
use std::env;
use std::io::{self, Write};
use std::process::Command;
use std::time::{Duration, SystemTime};

use bitcoin::consensus::deserialize;
use bitcoin::{Block, Transaction};
use bitcoin_pool_identification::PoolIdentification;
use colored::*;
use rawtx_rs::{input::InputType, output::OutputType, tx::TxInfo};
use zmq;

const ZMQ_ADDR: &str = "tcp://127.0.0.1:28332";
const TOPIC_RAWTX2: &str = "rawtxfee";
const TOPIC_RAWBLOCK: &str = "rawblock";
const TAPROOT_ACTIVATION_HEIGHT: u64 = 709632; //709632
const TAPROOT_ACTIVE_FIGLET: &str = r#"

         _____  _    ____  ____   ___   ___ _____
        |_   _|/ \  |  _ \|  _ \ / _ \ / _ \_   _|
          | | / _ \ | |_) | |_) | | | | | | || |
          | |/ ___ \|  __/|  _ <| |_| | |_| || |
          |_/_/   \_\_|   |_| \_\\___/ \___/ |_|

            _    ____ _____ _____     _______
           / \  / ___|_   _|_ _\ \   / / ____|
          / _ \| |     | |  | | \ \ / /|  _|
         / ___ \ |___  | |  | |  \ V / | |___
        /_/   \_\____| |_| |___|  \_/  |_____|
"#;

// TODO: make sure this can't crash during the stream

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        panic!("please provide exactly one argument");
    }

    let topic = &args[1];

    if !(topic == TOPIC_RAWTX2 || topic == TOPIC_RAWBLOCK) {
        panic!(
            "Invalid ZMQ topic. Use either '{}' or '{}'",
            TOPIC_RAWBLOCK, TOPIC_RAWTX2
        );
    }

    println!("Using topic {}", topic);

    let ctx = zmq::Context::new();

    let subscriber = ctx
        .socket(zmq::SUB)
        .expect("could not open new zmq::SUB socket");

    subscriber
        .connect(ZMQ_ADDR)
        .expect("subscriber could not connect to address");

    subscriber
        .set_rcvtimeo(1000)
        .expect("could not set the receive timeout");

    subscriber
        .set_subscribe(&topic.as_str().as_bytes())
        .expect("could not subscribe to empty topic");

    let mut non_p2tr_tx: u64 = 0;
    let mut time_last_block = SystemTime::now();

    for _ in 0..100 {
        println!("");
    }

    loop {
        if let Ok(msg) = subscriber.recv_multipart(0) {
            let msg_topic =
                std::str::from_utf8(&msg[0]).expect("msg0 (topic) is not parsable as utf8 string");
            non_p2tr_tx = process_message(msg_topic, &msg[1], non_p2tr_tx);
            if msg_topic == TOPIC_RAWBLOCK {
                time_last_block = SystemTime::now();
            }
        }
        if topic == TOPIC_RAWBLOCK {
            let duration = time_last_block.elapsed().unwrap();
            let seconds = duration.as_secs() % 60;
            let minutes = (duration.as_secs() / 60) % 60;
            let hours = (duration.as_secs() / 60) / 60;
            let mut time_str = format!("{}s", seconds);
            if minutes > 0 {
                time_str = format!("{}min {}", minutes, time_str);
            }
            if hours > 0 {
                time_str = format!("{}h {}", hours, time_str);
            }
            print!("\r\t{} since last block...", time_str.green());
            io::stdout().flush().unwrap();
        } else if topic == TOPIC_RAWTX2 {
            print!(
                "\r\t{} non-taproot transactions...",
                non_p2tr_tx.to_string().green()
            );
            io::stdout().flush().unwrap();
        }
    }
}

fn process_message(topic: &str, msg: &Vec<u8>, non_p2tr_tx: u64) -> u64 {
    match topic {
        TOPIC_RAWTX2 => return process_tx(&msg, non_p2tr_tx),
        TOPIC_RAWBLOCK => {
            process_block(&msg);
            return 0;
        }
        _ => return 0,
    };
}

fn process_block(rawblock: &Vec<u8>) {
    print!("\r");
    let block: Block = deserialize(&rawblock).expect("could not deserialize block");
    let height = block.bip34_block_height().unwrap();

    if height == TAPROOT_ACTIVATION_HEIGHT + 1 {
        println!(
            "{}",
            "*** FIRST TAPROOT BLOCK ***".bold().yellow().on_black()
        );
    }

    println!(
        "{}",
        format!("  Block {} ({})", height, block.block_hash())
            .bright_white()
            .bold()
    );

    let coinbase = block.txdata.first().unwrap();
    let coinbaseinfo = TxInfo::new(&coinbase).unwrap();

    let mut ascii_string: String = block.coinbase_script_as_utf8();
    ascii_string.retain(|c| !c.is_ascii_control());
    println!("\tCoinbase script: {}", ascii_string.cyan());
    println!("\tCoinbase value: {}", coinbaseinfo.output_value_sum());
    if let Some(pool) = block.identify_pool() {
        println!("\tMiner: {}", pool.name.yellow());
    } else {
        println!("\tMiner: {}", "Unknown Pool".yellow());
    }
    println!("\tTransactions: {}", block.txdata.len());
    let segwit_spending_tx = block
        .txdata
        .iter()
        .filter(|tx| TxInfo::new(&tx).unwrap().is_spending_segwit())
        .count();
    let taproot_spending_tx = block
        .txdata
        .iter()
        .filter(|tx| {
            TxInfo::new(&tx)
                .unwrap()
                .input_infos
                .iter()
                .any(|i| i.in_type == InputType::P2trkp || i.in_type == InputType::P2trsp)
        })
        .count();
    let taproot_paying_tx = block
        .txdata
        .iter()
        .filter(|tx| {
            TxInfo::new(&tx)
                .unwrap()
                .output_infos
                .iter()
                .any(|o| o.out_type == OutputType::P2tr)
        })
        .count();
    println!(
        "\tTransactions spending SegWit: {} ({:.2}%)",
        segwit_spending_tx,
        (segwit_spending_tx as f64 / block.txdata.len() as f64) * 100.0
    );
    if taproot_spending_tx > 0 {
        println!(
            "\tTransactions spending Taproot: {} ({:.2}%)",
            taproot_spending_tx,
            (taproot_spending_tx as f64 / block.txdata.len() as f64) * 100.0
        );
    }
    if taproot_paying_tx > 0 {
        println!(
            "\tTransactions paying to Pay-to-Taproot: {} ({:.2}%)",
            taproot_paying_tx,
            (taproot_paying_tx as f64 / block.txdata.len() as f64) * 100.0
        );
    }
    print_inputs_and_outputs(&coinbaseinfo);

    if height < TAPROOT_ACTIVATION_HEIGHT {
        let mut plural_blocks: &str = "";
        if TAPROOT_ACTIVATION_HEIGHT - height > 1 {
            plural_blocks = "s";
        }
        println!(
            "{}",
            format!(
                "\t{} block{} remaining until activation",
                TAPROOT_ACTIVATION_HEIGHT - height,
                plural_blocks
            )
            .yellow()
        );
    } else if height == TAPROOT_ACTIVATION_HEIGHT {
        println!("{}", TAPROOT_ACTIVE_FIGLET.bold().yellow().on_black());
        play_sound(Sound::Activation);
    }

    if height != TAPROOT_ACTIVATION_HEIGHT {
        play_sound(Sound::NewBlock);
    }

    println!("");
}

fn process_tx(rawtx: &Vec<u8>, non_p2tr_tx: u64) -> u64 {
    let fee: u64 = u64::from_le_bytes(rawtx[rawtx.len() - 8..].try_into().unwrap());
    let tx: Transaction =
        deserialize(&rawtx[..rawtx.len() - 8]).expect("could not deserialize transaction");
    let txinfo = TxInfo::new(&tx).unwrap();

    let spends_p2trkp = txinfo
        .input_infos
        .iter()
        .filter(|input| input.in_type == InputType::P2trkp)
        .count();
    let spends_p2trsp = txinfo
        .input_infos
        .iter()
        .filter(|input| input.in_type == InputType::P2trsp)
        .count();
    let paysto_p2tr = txinfo
        .output_infos
        .iter()
        .filter(|output| output.out_type == OutputType::P2tr)
        .count();

    if spends_p2trkp > 0 || spends_p2trsp > 0 || paysto_p2tr > 0 {
        print_transaction(&txinfo, &tx, fee);
        return 0;
    }

    return non_p2tr_tx + 1;
}

fn print_transaction(txinfo: &TxInfo, tx: &Transaction, fee: u64) {
    print!("\r");
    println!(
        "{}",
        format!("  Transaction {}", txinfo.txid)
            .bright_white()
            .bold()
    );
    println!("\tSize: {} vByte", txinfo.vsize);
    println!("\tFee: {} sat", fee);
    println!(
        "\tFeerate: {:.2} sat/vByte",
        fee as f64 / txinfo.vsize as f64
    );
    if txinfo.locktime.locktime > 0 {
        println!("\tLocktime: {}", txinfo.locktime.locktime.to_string());
    }
    println!("\tOutput sum: {} sat", txinfo.output_value_sum().as_sat());

    print_inputs_and_outputs(&txinfo);

    if txinfo.has_opreturn_output() {
        print_opreturn_outputs(&tx, &txinfo);
    }

    play_sound(Sound::NewP2TR);

    println!("");
}

fn print_inputs_and_outputs(txinfo: &TxInfo) {
    let mut inputs: HashMap<String, u32> = HashMap::new();
    let mut outputs: HashMap<String, u32> = HashMap::new();

    for input in txinfo.input_infos.iter() {
        *inputs.entry(input.in_type.to_string()).or_insert(0) += 1;
    }
    for output in txinfo.output_infos.iter() {
        *outputs.entry(output.out_type.to_string()).or_insert(0) += 1;
    }

    print!("\tInputs: ");
    for (i, (input_type, count)) in inputs.iter().enumerate() {
        if input_type.to_string().contains("P2TR") {
            print!(
                "{}",
                format!(" {}x {} ", count, input_type)
                    .black()
                    .on_green()
                    .bold()
            );
        } else {
            print!("{}x {}", count, input_type);
        }
        if i < inputs.len() - 1 {
            print!(", ");
        }
    }
    println!("");

    print!("\tOutputs: ");
    for (i, (output_type, count)) in outputs.iter().enumerate() {
        if output_type.to_string().contains("P2TR") {
            print!(
                "{}",
                format!(" {}x {} ", count, output_type)
                    .black()
                    .on_green()
                    .bold()
            );
        } else {
            print!("{}x {}", count, output_type);
        }
        if i < outputs.len() - 1 {
            print!(", ");
        }
    }
    println!("");
}

fn print_opreturn_outputs(tx: &Transaction, txinfo: &TxInfo) {
    for (i, output) in txinfo.output_infos.iter().enumerate() {
        if output.is_opreturn() {
            const MAX_OPPUSHBYTES_LEN: usize = 1 + 1 + 75; // OP_RETURN OP_PUSHBYTES_75 [75 bytes]
            let mut ascii_string: String;
            if tx.output[i].script_pubkey.len() > MAX_OPPUSHBYTES_LEN {
                // OP_RETURN is using OP_PUSHDATA_1
                ascii_string =
                    String::from_utf8_lossy(&tx.output[i].script_pubkey[3..]).to_string();
            } else {
                ascii_string =
                    String::from_utf8_lossy(&tx.output[i].script_pubkey[2..]).to_string();
            }
            ascii_string.retain(|c| !c.is_ascii_control());
            println!("\t  OP_RETURN: {}", ascii_string.cyan());
        }
    }
}

enum Sound {
    NewBlock,
    NewP2TR,
    Activation,
}

fn play_sound(sound: Sound) {
    let mp3_file: &str;

    match sound {
        Sound::NewBlock => mp3_file = "./definite.mp3",
        Sound::NewP2TR => mp3_file = "./p2tr.mp3",
        Sound::Activation => mp3_file = "./taproot-win.mp3",
    };

    std::thread::spawn(move || {
        Command::new("play").arg(mp3_file).arg("-q").output();
    });
}
