use super::x64;
use log::error;
use std::convert::{TryFrom, TryInto};
use std::result;
use thiserror::Error;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Register64 {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    Rip,
    Cr0,
    Efer,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum RegisterSegment {
    Es,
    Cs,
    Ss,
    Ds,
    Fs,
    Gs,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("unknown instruction {0:x}")]
    UnknownInstruction(u8),
}

type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub struct Value {
    pub length: u8,
    pub value: u128,
}

#[derive(Debug)]
pub enum Input<'a> {
    Start,
    Continue,
    Instructions(&'a [u8]),
    Register64(Register64, u64),
    Memory(Value),
}

#[derive(Debug)]
pub enum Output {
    GetInstructionStream,
    ReadRegister64(Register64),
    WriteRegister64(Register64, u64),
    ReadMemory(u8),
    WriteMemory(Value),
    Done,
}

enum State {
    GetProcessorState1,
    GetProcessorState2,
    GetProcessorState3,
    DecodePreamble,
    Decode,
    WriteRegister(Register64, u64),
    ReadModifyWriteRegister(Register64),
    WriteRegisterValueToMemory(Register64),
    AdvanceIp1,
    AdvanceIp2,
    Finished,
}

struct CpuState {
    protected_mode: bool,
    long_mode: bool,
}

struct RexPrefix {
    pub high_base_register: bool,
    pub high_index_register: bool,
    pub high_memory_register: bool,
    pub operand_size_64: bool,
}

impl RexPrefix {
    fn new(value: u8) -> Self {
        RexPrefix {
            high_base_register: (value & 0x01 != 0),
            high_index_register: (value & 0x02 != 0),
            high_memory_register: (value & 0x04 != 0),
            operand_size_64: (value & 0x08 != 0),
        }
    }
}

struct Preamble {
    pub size: u8,
    pub rex_prefix: RexPrefix,
    pub data_segment: RegisterSegment,
    pub op_size_override: bool,
    pub repz: bool,
    pub repnz: bool,
    pub lock: bool,
}

impl Preamble {
    fn new() -> Preamble {
        Preamble {
            size: 0,
            rex_prefix: RexPrefix::new(0),
            data_segment: RegisterSegment::Ds,
            op_size_override: false,
            repz: false,
            repnz: false,
            lock: false,
        }
    }
}

pub struct Emulator {
    state: State,
    cpu_state: CpuState,
    instruction_preamble: Preamble,
    instruction_size: u8,
    operand_size: u8,
}

fn to_register_name(index: u8) -> Result<Register64> {
    Ok(match index {
        0 => Register64::Rax,
        1 => Register64::Rcx,
        2 => Register64::Rdx,
        3 => Register64::Rbx,
        4 => Register64::Rsp,
        5 => Register64::Rbp,
        6 => Register64::Rsi,
        7 => Register64::Rdi,
        8 => Register64::R8,
        9 => Register64::R9,
        10 => Register64::R10,
        11 => Register64::R11,
        12 => Register64::R12,
        13 => Register64::R13,
        14 => Register64::R14,
        15 => Register64::R15,
        _ => return Err(Error::UnknownInstruction(1)),
    })
}

impl Emulator {
    pub fn new() -> Emulator {
        Emulator {
            state: State::GetProcessorState1,
            cpu_state: CpuState {
                protected_mode: true,
                long_mode: true,
            },
            instruction_preamble: Preamble::new(),
            instruction_size: 0,
            operand_size: 0,
        }
    }

    pub fn run(&mut self, input: &Input) -> Result<Output> {
        match self.state {
            State::GetProcessorState1 => self.get_processor_state1(input),
            State::GetProcessorState2 => self.get_processor_state2(input),
            State::GetProcessorState3 => self.get_processor_state3(input),
            State::DecodePreamble => self.decode_preamble(input),
            State::Decode => self.decode(input),
            State::WriteRegister(name, val) => self.write_register(input, name, val),
            State::ReadModifyWriteRegister(name) => self.read_modify_write_register(input, name),
            State::WriteRegisterValueToMemory(name) => self.write_register_to_memory(input, name),
            State::AdvanceIp1 => self.advance_ip1(),
            State::AdvanceIp2 => self.advance_ip2(input),
            State::Finished => Ok(Output::Done),
        }
    }

    // fetch CR0
    fn get_processor_state1(&mut self, input: &Input) -> Result<Output> {
        if let Input::Start = input {
        } else {
            panic!()
        }

        self.state = State::GetProcessorState2;
        Ok(Output::ReadRegister64(Register64::Cr0))
    }

    // Check for protected mode
    fn get_processor_state2(&mut self, input: &Input) -> Result<Output> {
        let (name, value) = match input {
            Input::Register64(name, value) => (*name, *value),
            _ => panic!(),
        };

        assert!(name == Register64::Cr0);

        let cr0 = value;
        self.cpu_state.protected_mode = (cr0 & x64::X64_CR0_PE) == x64::X64_CR0_PE;

        if self.cpu_state.protected_mode {
            // In protected mode, need to check extended feature register.
            self.state = State::GetProcessorState3;
            Ok(Output::ReadRegister64(Register64::Efer))
        } else {
            // In real mode, can start decoding instruction steam.
            self.state = State::DecodePreamble;
            Ok(Output::GetInstructionStream)
        }
    }

    // In protected mode, check extended feature register.
    fn get_processor_state3(&mut self, input: &Input) -> Result<Output> {
        let (name, value) = match input {
            Input::Register64(name, value) => (*name, *value),
            _ => panic!(),
        };

        assert!(self.cpu_state.protected_mode);
        assert!(name == Register64::Efer);

        let efer = value;
        self.cpu_state.long_mode = (efer & x64::X64_EFER_LMA) == x64::X64_EFER_LMA;
        self.state = State::DecodePreamble;
        Ok(Output::GetInstructionStream)
    }

    fn decode_preamble(&mut self, input: &Input) -> Result<Output> {
        let instruction_stream: &[u8];
        match input {
            Input::Instructions(stream) => instruction_stream = stream,
            _ => panic!(),
        }

        if instruction_stream.is_empty() {
            return Err(Error::UnknownInstruction(2));
        }

        let mut preamble = &mut self.instruction_preamble;
        for instruction in instruction_stream.iter().enumerate() {
            let opcode = *instruction.1;
            match opcode {
                0x26 if self.cpu_state.long_mode => preamble.data_segment = RegisterSegment::Es,
                0x2E if self.cpu_state.long_mode => preamble.data_segment = RegisterSegment::Cs,
                0x36 if self.cpu_state.long_mode => preamble.data_segment = RegisterSegment::Ss,
                0x3E if self.cpu_state.long_mode => preamble.data_segment = RegisterSegment::Ds,
                0x64 => preamble.data_segment = RegisterSegment::Fs,
                0x65 => preamble.data_segment = RegisterSegment::Gs,
                0x66 => preamble.op_size_override = true,
                0x67 => (), // address register size override
                0xF0 => preamble.lock = true,
                0xF2 => preamble.repnz = true,
                0xF3 => preamble.repz = true,
                _ if !self.cpu_state.long_mode || opcode & 0xf0 != 0x40 => {
                    preamble.size = u8::try_from(instruction.0).expect("bad instruction stream");
                    break;
                }
                _ => {
                    preamble.rex_prefix = RexPrefix::new(opcode);
                }
            }
        }

        self.state = State::Decode;
        Ok(Output::GetInstructionStream)
    }

    // returns the number of bytes in the instruction used to store the offset (for 32/64 bit CPU mode)
    fn get_modrm_address_offset_bytes(&self, modrm: u8) -> u8 {
        if modrm < 0x40 {
            match modrm {
                0x04 => 1,
                0x05 => 4,
                0x0c => 1,
                0x0d => 4,
                0x14 => 1,
                0x15 => 4,
                0x1c => 1,
                0x1d => 4,
                0x24 => 1,
                0x25 => 4,
                0x2c => 1,
                0x2d => 4,
                0x34 => 1,
                0x35 => 4,
                0x3c => 1,
                0x3d => 4,
                _ => 0,
            }
        } else if modrm < 0x80 {
            match modrm {
                0x44 => 2,
                0x4c => 2,
                0x54 => 2,
                0x5c => 2,
                0x64 => 2,
                0x6c => 2,
                0x74 => 2,
                0x7c => 2,
                _ => 1,
            }
        } else if modrm < 0xc0 {
            match modrm {
                0x84 => 5,
                0x8c => 5,
                0x94 => 5,
                0x9c => 5,
                0xa4 => 5,
                0xac => 5,
                0xb4 => 5,
                0xbc => 5,
                _ => 4,
            }
        } else {
            0
        }
    }

    fn modrm_extra_instruction_bytes(&self, instruction_stream: &[u8]) -> u8 {
        let modrm = instruction_stream[0];
        let length = self.get_modrm_address_offset_bytes(modrm);

        // the index register is modrm & 7 with rex_prefix.high_index_register, but only checking here for the special
        // value indicating extra index byte.
        let use_index_byte = modrm & 7 == 4;

        if use_index_byte {
            let sib = instruction_stream[1];
            // actual index registers are (sib & 0x38 >> 3) and (sib & 7) including rex_prefix.high_base_register
            let use_imm = sib & 7 == 5;
            if use_imm {
                // instead of a second register index, use a 4-byte immediate address
                length + 4
            } else {
                // no special handling, length already includes the extra index byte
                length
            }
        } else {
            length
        }
    }

    fn decode(&mut self, input: &Input) -> Result<Output> {
        let instruction_stream: &[u8];
        match input {
            Input::Instructions(stream) => instruction_stream = stream,
            _ => panic!(),
        }

        if instruction_stream.is_empty() {
            return Err(Error::UnknownInstruction(3));
        }

        let i = self.instruction_preamble.size as usize;
        if instruction_stream.len() < i + 1 {
            return Err(Error::UnknownInstruction(4));
        }

        self.operand_size = if self.instruction_preamble.rex_prefix.operand_size_64 {
            8
        } else if self.instruction_preamble.op_size_override {
            2
        } else {
            4
        };

        let result: Output;
        match instruction_stream[i] {
            0x88 | 0x89 => {
                if instruction_stream.len() < 2 + i {
                    return Err(Error::UnknownInstruction(5));
                }

                if instruction_stream[i] == 0x88 {
                    self.operand_size = 1;
                }

                let mode = (instruction_stream[i + 1] & 0xc0) >> 6;
                if mode == 3 {
                    // Target is a register. This can be emulated, but why?
                    return Err(Error::UnknownInstruction(6));
                }

                let reg = (instruction_stream[i + 1] & 0x38) >> 3
                    | match self.instruction_preamble.rex_prefix.high_memory_register {
                        true => 8,
                        false => 0,
                    };

                let reg = to_register_name(reg)?;
                self.instruction_size =
                    2 + self.modrm_extra_instruction_bytes(&instruction_stream[i + 1..]);
                self.state = State::WriteRegisterValueToMemory(reg);
                result = Output::ReadRegister64(reg);
            }
            0x8a | 0x8b => {
                if instruction_stream.len() < 2 + i {
                    return Err(Error::UnknownInstruction(7));
                }

                if instruction_stream[i] == 0x8a {
                    self.operand_size = 1;
                }

                let mode = (instruction_stream[i + 1] & 0xc0) >> 6;
                if mode == 3 {
                    // Target is a register. This can be emulated, but why?
                    return Err(Error::UnknownInstruction(8));
                }

                let reg = (instruction_stream[i + 1] & 0x38) >> 3
                    | match self.instruction_preamble.rex_prefix.high_memory_register {
                        true => 8,
                        false => 0,
                    };

                let reg = to_register_name(reg)?;
                self.instruction_size =
                    2 + self.modrm_extra_instruction_bytes(&instruction_stream[i + 1..]);
                if self.operand_size < 8 {
                    self.state = State::ReadModifyWriteRegister(reg);
                    result = Output::ReadRegister64(reg);
                } else {
                    self.state = State::WriteRegister(reg, 0);
                    result = Output::ReadMemory(self.operand_size);
                };
            }
            0xc6 | 0xc7 => {
                // mov _, imm
                if instruction_stream[i] == 0xc6 {
                    self.operand_size = 1;
                }
                let imm_size = match self.operand_size {
                    1 => 1,
                    2 => 2,
                    _ => 4,
                };

                if instruction_stream.len() < 2 + imm_size + i {
                    return Err(Error::UnknownInstruction(7));
                }

                let mode = (instruction_stream[i + 1] & 0xc0) >> 6;
                if mode == 3 {
                    // Target is a register. This can be emulated, but why?
                    return Err(Error::UnknownInstruction(6));
                }

                let n = self.modrm_extra_instruction_bytes(&instruction_stream[i + 1..]) as usize;
                let imm = instruction_stream
                    .get(i + 2 + n..i + 2 + n + imm_size)
                    .ok_or(Error::UnknownInstruction(11))?;
                let value: i64 = match imm_size {
                    1 => imm[0].into(),
                    2 => u16::from_ne_bytes(imm[0..2].try_into().unwrap()).into(),
                    _ => i32::from_ne_bytes(imm[0..4].try_into().unwrap()).into(), // sign extend
                };

                self.instruction_size = 2 + n as u8 + imm_size as u8;
                self.state = State::AdvanceIp1;
                result = Output::WriteMemory(Value {
                    length: self.operand_size as u8,
                    value: (value as u64).into(),
                });
            }
            _ => {
                error!("[Emulator] {:x?}", instruction_stream);
                return Err(Error::UnknownInstruction(9));
            }
        }

        Ok(result)
    }

    fn read_modify_write_register(
        &mut self,
        input: &Input,
        reg_name: Register64,
    ) -> Result<Output> {
        let (name, value) = match input {
            Input::Register64(x, y) => (*x, *y),
            _ => panic!(),
        };

        assert!(name == reg_name);

        self.state = State::WriteRegister(name, value);
        Ok(Output::ReadMemory(self.operand_size))
    }

    fn write_register(
        &mut self,
        input: &Input,
        reg_name: Register64,
        old_value: u64,
    ) -> Result<Output> {
        let value: &Value;
        match input {
            Input::Memory(val) => value = val,
            _ => panic!(),
        }

        assert!(value.length <= 8);

        let registry_mask = u64::max_value() >> (8 * (8 - self.operand_size as u64));
        let data = value.value & (u128::max_value() >> (8 * (16 - value.length)));
        let data = u64::try_from(data).expect("Unexpected failure") & registry_mask
            | (old_value & !registry_mask);
        self.state = State::AdvanceIp1;
        Ok(Output::WriteRegister64(reg_name, data))
    }

    fn write_register_to_memory(
        &mut self,
        input: &Input,
        expected_register: Register64,
    ) -> Result<Output> {
        let (name, value) = match input {
            Input::Register64(x, y) => (*x, *y),
            _ => panic!(),
        };

        assert!(name == expected_register);

        self.state = State::AdvanceIp1;
        Ok(Output::WriteMemory(Value {
            length: self.operand_size,
            value: value as u128 & (u128::max_value() >> (8 * (16 - self.operand_size))),
        }))
    }

    // get the current IP
    fn advance_ip1(&mut self) -> Result<Output> {
        self.state = State::AdvanceIp2;
        Ok(Output::ReadRegister64(Register64::Rip))
    }

    // skip past the instruction stream that was executed.
    fn advance_ip2(&mut self, input: &Input) -> Result<Output> {
        let (name, value) = match input {
            Input::Register64(name, value) => (*name, *value),
            _ => panic!(),
        };

        assert!(name == Register64::Rip);

        let next_ip = value;
        let next_ip = next_ip + (self.instruction_preamble.size + self.instruction_size) as u64;
        self.state = State::Finished;
        Ok(Output::WriteRegister64(Register64::Rip, next_ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn long_protected_mode(
        emul: &mut Emulator,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let emulator_input = Input::Start;
        if let Output::ReadRegister64(register_name) = emul.run(&emulator_input)? {
            assert_eq!(register_name, Register64::Cr0);
        } else {
            panic!("Expecting read of CR0 register.");
        }

        let emulator_input = Input::Register64(Register64::Cr0, 1);

        if let Output::ReadRegister64(register_name) = emul.run(&emulator_input)? {
            assert_eq!(register_name, Register64::Efer);
        } else {
            panic!("Expecting read of Efer register.");
        }

        let emulator_input = Input::Register64(Register64::Efer, 0x400);

        if let Output::GetInstructionStream = emul.run(&emulator_input)? {
        } else {
            panic!("Expecting instruction fetch.");
        }

        Ok(())
    }

    fn advance_instruction_pointer(
        emul: &mut Emulator,
    ) -> std::result::Result<u64, Box<dyn std::error::Error>> {
        let emulator_input = Input::Continue;
        if let Output::ReadRegister64(register_name) = emul.run(&emulator_input)? {
            assert_eq!(register_name, Register64::Rip);
        } else {
            panic!("Expecting read of RIP register.");
        }

        let emulator_input = Input::Register64(Register64::Rip, 0xffff0000);

        let instruction_length: u64;
        if let Output::WriteRegister64(name, value) = emul.run(&emulator_input)? {
            assert_eq!(name, Register64::Rip);
            instruction_length = value - 0xffff0000;
        } else {
            panic!("Expecting write of RIP register.");
        }

        let emulator_input = Input::Continue;
        if let Output::Done = emul.run(&emulator_input)? {
        } else {
            panic!("Expecting emulator to be finished.");
        }

        Ok(instruction_length)
    }

    #[test]
    fn mov_regvalue_to_memory() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut emul = Emulator::new();
        long_protected_mode(&mut emul)?;

        // mov dword ptr [rax],esi
        let emulator_input = Input::Instructions(&[0x89, 0x30]);
        if let Output::GetInstructionStream = emul.run(&emulator_input)? {
        } else {
            panic!("Expecting instruction fetch.");
        }

        if let Output::ReadRegister64(register_name) = emul.run(&emulator_input)? {
            assert_eq!(register_name, Register64::Rsi);
        } else {
            panic!("Expecting read of RSI register.");
        }

        let emulator_input = Input::Register64(Register64::Rsi, 0x123);

        if let Output::WriteMemory(write_value) = emul.run(&emulator_input)? {
            assert_eq!(write_value.length, 4);
            assert_eq!(write_value.value, 0x123);
        } else {
            panic!("Expecting memory write");
        }

        assert_eq!(advance_instruction_pointer(&mut emul)?, 2);

        Ok(())
    }

    #[test]
    fn mov_regvalue_to_memory_8bit() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut emul = Emulator::new();
        long_protected_mode(&mut emul)?;

        // mov byte ptr [rax],dh
        let emulator_input = Input::Instructions(&[0x88, 0x30]);
        if let Output::GetInstructionStream = emul.run(&emulator_input)? {
        } else {
            panic!("Expecting instruction fetch.");
        }

        if let Output::ReadRegister64(register_name) = emul.run(&emulator_input)? {
            assert_eq!(register_name, Register64::Rsi);
        } else {
            panic!("Expecting read of RSI register.");
        }

        let emulator_input = Input::Register64(Register64::Rsi, 0x123);

        if let Output::WriteMemory(write_value) = emul.run(&emulator_input)? {
            assert_eq!(write_value.length, 1);
            assert_eq!(write_value.value, 0x23);
        } else {
            panic!("Expecting memory write");
        }

        assert_eq!(advance_instruction_pointer(&mut emul)?, 2);

        Ok(())
    }

    #[test]
    fn mov_regvalue_to_memory_imm32() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut emul = Emulator::new();
        long_protected_mode(&mut emul)?;

        // mov dword ptr [rax+0x00000001],edi
        let emulator_input = Input::Instructions(&[0x89, 0x3c, 0x05, 0x01, 0x00, 0x00, 0x00]);
        if let Output::GetInstructionStream = emul.run(&emulator_input)? {
        } else {
            panic!("Expecting instruction fetch.");
        }

        if let Output::ReadRegister64(register_name) = emul.run(&emulator_input)? {
            assert_eq!(register_name, Register64::Rdi);
        } else {
            panic!("Expecting read of RSI register.");
        }

        let emulator_input = Input::Register64(Register64::Rdi, 0x123);

        if let Output::WriteMemory(write_value) = emul.run(&emulator_input)? {
            assert_eq!(write_value.length, 4);
            assert_eq!(write_value.value, 0x123);
        } else {
            panic!("Expecting memory write");
        }

        assert_eq!(advance_instruction_pointer(&mut emul)?, 7);

        Ok(())
    }

    #[test]
    fn mov_memory_to_regvalue() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut emul = Emulator::new();
        long_protected_mode(&mut emul)?;

        // mov eax,dword ptr [rax+10h]
        let emulator_input = Input::Instructions(&[0x8b, 0x40, 0x10]);
        if let Output::GetInstructionStream = emul.run(&emulator_input)? {
        } else {
            panic!("Expecting instruction fetch.");
        }

        if let Output::ReadRegister64(register_name) = emul.run(&emulator_input)? {
            assert_eq!(register_name, Register64::Rax);
        } else {
            panic!("Expecting registry read");
        }

        let emulator_input = Input::Register64(Register64::Rax, 0x12345678ffffffff);

        if let Output::ReadMemory(size) = emul.run(&emulator_input)? {
            assert_eq!(size, 4);
        } else {
            panic!("Expecting memory write");
        }

        let emulator_input = Input::Memory(Value {
            length: 8,
            value: 0x123,
        });

        if let Output::WriteRegister64(name, value) = emul.run(&emulator_input)? {
            assert_eq!(name, Register64::Rax);
            assert_eq!(value, 0x1234567800000123);
        } else {
            panic!("Expecting write of RAX register.");
        }

        assert_eq!(advance_instruction_pointer(&mut emul)?, 3);

        Ok(())
    }

    #[test]
    fn mov_memory_to_regvalue_8bit() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut emul = Emulator::new();
        long_protected_mode(&mut emul)?;

        // mov al,byte ptr [rax+10h]
        let emulator_input = Input::Instructions(&[0x8a, 0x40, 0x10]);
        if let Output::GetInstructionStream = emul.run(&emulator_input)? {
        } else {
            panic!("Expecting instruction fetch.");
        }

        if let Output::ReadRegister64(register_name) = emul.run(&emulator_input)? {
            assert_eq!(register_name, Register64::Rax);
        } else {
            panic!("Expecting registry read");
        }

        let emulator_input = Input::Register64(Register64::Rax, 0x12345678abcdefff);

        if let Output::ReadMemory(size) = emul.run(&emulator_input)? {
            assert_eq!(size, 1);
        } else {
            panic!("Expecting memory write");
        }

        let emulator_input = Input::Memory(Value {
            length: 8,
            value: 0xffffffffffffff12,
        });

        if let Output::WriteRegister64(name, value) = emul.run(&emulator_input)? {
            assert_eq!(name, Register64::Rax);
            assert_eq!(value, 0x12345678abcdef12);
        } else {
            panic!("Expecting write of RAX register.");
        }

        assert_eq!(advance_instruction_pointer(&mut emul)?, 3);

        Ok(())
    }

    #[test]
    fn mov_memory_to_regvalue64_two_indices() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let mut emul = Emulator::new();
        long_protected_mode(&mut emul)?;

        // mov rax, [rax+rax]
        let emulator_input = Input::Instructions(&[0x48, 0x8b, 0x04, 0x00]);
        if let Output::GetInstructionStream = emul.run(&emulator_input)? {
        } else {
            panic!("Expecting instruction fetch.");
        }

        if let Output::ReadMemory(size) = emul.run(&emulator_input)? {
            assert_eq!(size, 8);
        } else {
            panic!("Expecting memory write");
        }

        let emulator_input = Input::Memory(Value {
            length: 8,
            value: 0x123,
        });

        if let Output::WriteRegister64(name, value) = emul.run(&emulator_input)? {
            assert_eq!(name, Register64::Rax);
            assert_eq!(value, 0x123);
        } else {
            panic!("Expecting write of RAX register.");
        }

        assert_eq!(advance_instruction_pointer(&mut emul)?, 4);

        Ok(())
    }
}
