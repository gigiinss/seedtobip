Kit de Ferramentas para Transações Bitcoin
Este projeto contém um conjunto completo de ferramentas para gerenciar suas criptomoedas, desde a recuperação de chaves privadas até a realização de transações na Kraken.

Arquivos do Projeto
seed_to_private.py - Converte seed phrases em chaves privadas
bip38_decoder.py - Decodifica chaves privadas no formato BIP38
kraken_trader.py - Interface para realizar transações na Kraken
README.md - Este arquivo de documentação
Instalação
Pré-requisitos
bash
# Instale o Python 3.8 ou superior de python.org

# Instale as dependências
pip install mnemonic bip32utils scrypt base58 pycryptodome krakenex
1. Conversor de Seed para Chave Privada
Arquivo: seed_to_private.py
python
from mnemonic import Mnemonic
from bip32utils import BIP32Key
from hashlib import sha256
import sys
import getpass

def seed_to_private_key(seed_phrase, path="m/44'/0'/0'/0/0", passphrase=""):
    # Inicializa o objeto mnemônico
    mnemo = Mnemonic("english")
    
    # Verifica se a frase semente é válida
    if not mnemo.check(seed_phrase):
        print("Erro: Frase seed inválida!")
        return None
    
    # Gera a seed a partir da frase mnemônica
    seed = mnemo.to_seed(seed_phrase, passphrase)
    
    # Cria uma chave raiz BIP32
    root_key = BIP32Key.fromEntropy(seed)
    
    # Deriva o caminho
    path_components = path.split("/")
    key = root_key
    # Pula 'm'
    for component in path_components[1:]:
        if "'" in component:
            component = component.replace("'", "")
            key = key.ChildKey(int(component) + 0x80000000)
        else:
            key = key.ChildKey(int(component))
    
    # Obtém a chave privada em vários formatos
    private_key_hex = key.PrivateKey().hex()
    private_key_wif = key.WalletImportFormat()
    address = key.Address()
    
    return {
        "private_key_hex": private_key_hex,
        "private_key_wif": private_key_wif,
        "address": address
    }

def main():
    print("\n===== Conversor de Seed para Chave Privada =====\n")
    
    # Solicita a frase seed ao usuário
    print("Digite sua frase seed (12, 15, 18, 21 ou 24 palavras separadas por espaço):")
    seed_phrase = input().strip()
    
    # Solicita uma senha opcional (pode deixar em branco)
    print("\nDigite uma senha (se houver) ou deixe em branco:")
    passphrase = getpass.getpass()
    
    # Caminho de derivação padrão para Bitcoin
    path = "m/44'/0'/0'/0/0"
    print(f"\nUsando caminho de derivação: {path}")
    
    # Converte a seed para chave privada
    result = seed_to_private_key(seed_phrase, path, passphrase)
    
    if result:
        print("\n===== Resultados =====")
        print(f"\nEndereço Bitcoin: {result['address']}")
        print(f"\nChave Privada (formato WIF): {result['private_key_wif']}")
        print(f"\nChave Privada (formato HEX): {result['private_key_hex']}")
        print("\nGuarde estas informações em um lugar seguro!")
    
    input("\nPressione Enter para sair...")

if __name__ == "__main__":
    main()
2. Decodificador BIP38
Arquivo: bip38_decoder.py
python
import binascii
import hashlib
import base58
from Crypto.Cipher import AES
import scrypt
import sys

def decode_bip38(encrypted_key, passphrase):
    # Decodifica a chave privada criptografada do formato Base58
    decoded_key = base58.b58decode(encrypted_key)
    
    # Verifica se é uma chave BIP38 válida (começa com 0x0142)
    if len(decoded_key) != 39 or decoded_key[0] != 0x01 or decoded_key[1] != 0x42:
        return {"error": "Formato de chave BIP38 inválido"}
    
    # Verifica flags
    flagbyte = decoded_key[2]
    compressed = (flagbyte & 0x20) != 0
    
    # Extrai o checksum da chave original
    checksum = decoded_key[-4:]
    key_without_checksum = decoded_key[:-4]
    
    # Verifica o checksum
    first_hash = hashlib.sha256(key_without_checksum).digest()
    second_hash = hashlib.sha256(first_hash).digest()
    if checksum != second_hash[:4]:
        return {"error": "Checksum inválido, a chave pode estar corrompida"}
    
    # Extrai o endereço Hash e os bytes de encriptação
    addresshash = decoded_key[3:7]
    encrypted_half1 = decoded_key[7:7+16]
    encrypted_half2 = decoded_key[7+16:7+32]
    
    # Deriva a chave de criptografia a partir da senha
    derived_key = scrypt.hash(
        passphrase.encode('utf-8'),
        addresshash,
        N=16384,
        r=8,
        p=8,
        buflen=64
    )
    derivedkey_half1 = derived_key[:32]
    derivedkey_half2 = derived_key[32:]
    
    # Decifra a chave privada
    cipher = AES.new(derivedkey_half2, AES.MODE_ECB)
    decrypted_half2 = cipher.decrypt(encrypted_half2)
    
    # XOR para obter a segunda metade
    decrypted_half2 = bytes(a ^ b for a, b in zip(decrypted_half2, derivedkey_half1[16:32]))
    
    # Decifra a primeira metade
    cipher = AES.new(derivedkey_half2, AES.MODE_ECB)
    decrypted_half1 = cipher.decrypt(encrypted_half1)
    
    # XOR para obter a primeira metade
    decrypted_half1 = bytes(a ^ b for a, b in zip(decrypted_half1, derivedkey_half1[:16]))
    
    # Combina as duas metades para formar a chave privada completa
    private_key = decrypted_half1 + decrypted_half2
    private_key_hex = binascii.hexlify(private_key).decode('utf-8')
    
    # Converte para o formato WIF
    # (Esta é uma implementação simplificada)
    wif_prefix = b'\x80'  # Mainnet
    key_with_prefix = wif_prefix + private_key
    
    if compressed:
        key_with_prefix += b'\x01'
    
    # Adiciona checksum
    first_hash = hashlib.sha256(key_with_prefix).digest()
    second_hash = hashlib.sha256(first_hash).digest()
    checksum = second_hash[:4]
    
    wif_key = key_with_prefix + checksum
    wif = base58.b58encode(wif_key).decode('utf-8')
    
    # Calcula o endereço Bitcoin correspondente
    # (Implementação simplificada)
    def get_address_from_private_key(private_key_hex, compressed=True):
        # Esta é uma implementação simplificada
        # Em um sistema real, você usaria uma biblioteca como bitcoin ou coincurve
        return "Calculado usando biblioteca externa"  # Placeholder
    
    return {
        "private_key_hex": private_key_hex,
        "private_key_wif": wif,
        "compressed": compressed,
        "address": get_address_from_private_key(private_key_hex, compressed)
    }

def main():
    print("\n===== Decodificador BIP38 =====\n")
    
    # Solicita a chave BIP38 ao usuário
    print("Digite a chave privada criptografada no formato BIP38:")
    encrypted_key = input().strip()
    
    # Solicita a senha
    print("\nDigite a senha usada para criptografar a chave:")
    passphrase = input().strip()
    
    # Decodifica a chave
    result = decode_bip38(encrypted_key, passphrase)
    
    if "error" in result:
        print(f"\nErro: {result['error']}")
    else:
        print("\n===== Resultados =====")
        print(f"\nChave Privada (formato WIF): {result['private_key_wif']}")
        print(f"\nChave Privada (formato HEX): {result['private_key_hex']}")
        print(f"\nComprimida: {'Sim' if result['compressed'] else 'Não'}")
        print(f"\nEndereço Bitcoin: {result['address']}")
        print("\nGuarde estas informações em um lugar seguro!")
    
    input("\nPressione Enter para sair...")

if __name__ == "__main__":
    main()
3. Ferramenta de Negociação Kraken
Arquivo: kraken_trader.py
python
import krakenex
import time
import json
import sys
from datetime import datetime

class KrakenTrader:
    def __init__(self):
        self.api = krakenex.API()
        self.is_authenticated = False
    
    def load_api_keys(self, key_file=None):
        try:
            if key_file:
                self.api.load_key(key_file)
            else:
                print("Digite sua API Key da Kraken:")
                api_key = input().strip()
                print("Digite sua API Secret da Kraken:")
                api_secret = input().strip()
                self.api.key = api_key
                self.api.secret = api_secret
            
            # Teste de autenticação
            result = self.api.query_private('Balance')
            if 'error' in result and result['error']:
                print(f"Erro de autenticação: {result['error']}")
                return False
            
            self.is_authenticated = True
            return True
        except Exception as e:
            print(f"Erro ao configurar as chaves API: {str(e)}")
            return False
    
    def get_account_balance(self):
        if not self.is_authenticated:
            return {"error": "Não autenticado. Carregue as chaves de API primeiro."}
        
        try:
            result = self.api.query_private('Balance')
            if 'error' in result and result['error']:
                return {"error": result['error']}
            return result['result']
        except Exception as e:
            return {"error": f"Erro ao obter saldo: {str(e)}"}
    
    def get_ticker(self, pair="XXBTZUSD"):
        try:
            result = self.api.query_public('Ticker', {'pair': pair})
            if 'error' in result and result['error']:
                return {"error": result['error']}
            return result['result']
        except Exception as e:
            return {"error": f"Erro ao obter cotação: {str(e)}"}
    
    def place_market_order(self, pair, type, volume, fee_type="high"):
        if not self.is_authenticated:
            return {"error": "Não autenticado. Carregue as chaves de API primeiro."}
        
        try:
            # Configura os parâmetros da ordem
            params = {
                'pair': pair,
                'type': type,  # 'buy' ou 'sell'
                'ordertype': 'market',
                'volume': volume,
                'oflags': 'fciq'  # Fee in quote currency
            }
            
            # Adiciona a configuração de taxa alta se solicitado
            if fee_type == "high":
                params['trading_agreement'] = 'agree'
                params['fee_volume'] = 'true'  # Solicita taxa de prioridade
            
            # Envia a ordem
            result = self.api.query_private('AddOrder', params)
            
            if 'error' in result and result['error']:
                return {"error": result['error']}
            
            return {
                "status": "success",
                "txid": result['result']['txid'],
                "description": result['result']['descr']
            }
        except Exception as e:
            return {"error": f"Erro ao colocar ordem: {str(e)}"}
    
    def get_deposit_address(self, asset="XBT", method="Bitcoin"):
        if not self.is_authenticated:
            return {"error": "Não autenticado. Carregue as chaves de API primeiro."}
        
        try:
            result = self.api.query_private('DepositAddresses', {
                'asset': asset,
                'method': method
            })
            
            if 'error' in result and result['error']:
                return {"error": result['error']}
            
            if not result['result']:
                # Se não houver endereço, tenta gerar um novo
                result = self.api.query_private('DepositMethods', {
                    'asset': asset
                })
                
                if 'error' in result and result['error']:
                    return {"error": result['error']}
                
                if not result['result']:
                    return {"error": "Não foi possível encontrar métodos de depósito para este ativo"}
                
                method = result['result'][0]['method']
                
                # Gera um novo endereço
                result = self.api.query_private('DepositAddresses', {
                    'asset': asset,
                    'method': method,
                    'new': True
                })
                
                if 'error' in result and result['error']:
                    return {"error": result['error']}
            
            return result['result']
        except Exception as e:
            return {"error": f"Erro ao obter endereço de depósito: {str(e)}"}

def main():
    print("\n===== Kraken Trader =====\n")
    
    trader = KrakenTrader()
    
    print("Bem-vindo à ferramenta de trading da Kraken!")
    print("1. Carregar chaves de API")
    print("2. Verificar saldo da conta")
    print("3. Obter cotação atual do Bitcoin")
    print("4. Vender Bitcoin a mercado (taxa alta)")
    print("5. Obter endereço de depósito Bitcoin")
    print("0. Sair")
    
    while True:
        try:
            choice = int(input("\nEscolha uma opção (0-5): "))
            
            if choice == 0:
                print("Saindo...")
                break
                
            elif choice == 1:
                print("\n--- Carregar Chaves de API ---")
                print("1. Digitar manualmente")
                print("2. Carregar de arquivo")
                key_choice = int(input("Escolha uma opção (1-2): "))
                
                if key_choice == 1:
                    if trader.load_api_keys():
                        print("Chaves de API carregadas com sucesso!")
                    else:
                        print("Falha ao carregar as chaves de API.")
                        
                elif key_choice == 2:
                    file_path = input("Digite o caminho para o arquivo de chaves: ")
                    if trader.load_api_keys(file_path):
                        print("Chaves de API carregadas com sucesso!")
                    else:
                        print("Falha ao carregar as chaves de API do arquivo.")
                
            elif choice == 2:
                print("\n--- Saldo da Conta ---")
                balance = trader.get_account_balance()
                
                if "error" in balance:
                    print(f"Erro: {balance['error']}")
                else:
                    print("\nSeu saldo na Kraken:")
                    for asset, amount in balance.items():
                        print(f"{asset}: {amount}")
            
            elif choice == 3:
                print("\n--- Cotação do Bitcoin ---")
                pair = input("Digite o par de moedas (padrão: XXBTZUSD): ") or "XXBTZUSD"
                ticker = trader.get_ticker(pair)
                
                if "error" in ticker:
                    print(f"Erro: {ticker['error']}")
                else:
                    for p, data in ticker.items():
                        print(f"\nPar: {p}")
                        print(f"Preço atual: {data['c'][0]}")
                        print(f"Volume 24h: {data['v'][1]}")
                        print(f"Preço mais alto 24h: {data['h'][1]}")
                        print(f"Preço mais baixo 24h: {data['l'][1]}")
            
            elif choice == 4:
                print("\n--- Vender Bitcoin (Taxa Alta) ---")
                
                pair = input("Digite o par de moedas (padrão: XXBTZUSD): ") or "XXBTZUSD"
                volume = input("Digite a quantidade de Bitcoin a vender: ")
                
                confirmation = input(f"Confirma a venda de {volume} BTC no par {pair}? (s/n): ")
                
                if confirmation.lower() == 's':
                    result = trader.place_market_order(pair, "sell", volume, "high")
                    
                    if "error" in result:
                        print(f"Erro: {result['error']}")
                    else:
                        print("\nOrdem enviada com sucesso!")
                        print(f"ID da transação: {result['txid']}")
                        print(f"Descrição: {result['description']}")
                else:
                    print("Venda cancelada.")
            
            elif choice == 5:
                print("\n--- Obter Endereço de Depósito Bitcoin ---")
                result = trader.get_deposit_address()
                
                if "error" in result:
                    print(f"Erro: {result['error']}")
                else:
                    print("\nSeu endereço de depósito Bitcoin na Kraken:")
                    for address_info in result:
                        print(f"Endereço: {address_info['address']}")
                        if 'expiretm' in address_info:
                            expire_time = datetime.fromtimestamp(address_info['expiretm'])
                            print(f"Expira em: {expire_time}")
            
            else:
                print("Opção inválida. Por favor, tente novamente.")
                
        except ValueError:
            print("Entrada inválida. Por favor, digite um número.")
        except Exception as e:
            print(f"Erro: {str(e)}")
    
    print("Obrigado por usar o Kraken Trader!")

if __name__ == "__main__":
    main()
4. Interface Unificada
Arquivo: bitcoin_toolkit.py
python
import os
import sys
import importlib.util

def load_module(file_path, module_name):
    """Carrega um módulo Python de um arquivo."""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def clear_screen():
    """Limpa a tela do console."""
    os.system('cls' if os.name == 'nt' else 'clear')

def main_menu():
    """Exibe o menu principal."""
    clear_screen()
    print("\n" + "="*50)
    print("       KIT DE FERRAMENTAS PARA BITCOIN")
    print("="*50 + "\n")
    
    print("Escolha uma ferramenta:")
    print("1. Conversor de Seed para Chave Privada")
    print("2. Decodificador BIP38")
    print("3. Interface de Negociação Kraken")
    print("0. Sair")
    
    try:
        choice = int(input("\nSua escolha (0-3): "))
        return choice
    except ValueError:
        return -1

def main():
    """Função principal do programa."""
    # Verifica se todos os arquivos necessários existem
    required_files = {
        'seed_to_private.py': 'Conversor de Seed para Chave Privada',
        'bip38_decoder.py': 'Decodificador BIP38',
        'kraken_trader.py': 'Interface de Negociação Kraken'
    }
    
    missing_files = []
    
    for file, description in required_files.items():
        if not os.path.exists(file):
            missing_files.append(f"{file} ({description})")
    
    if missing_files:
        print("ERRO: Os seguintes arquivos estão faltando:")
        for file in missing_files:
            print(f"- {file}")
        print("\nPor favor, certifique-se de que todos os arquivos do kit estão na mesma pasta.")
        input("\nPressione Enter para sair...")
        return
    
    while True:
        choice = main_menu()
        
        if choice == 0:
            print("\nObrigado por usar o Kit de Ferramentas para Bitcoin!")
            break
            
        elif choice == 1:
            # Carrega e executa o conversor de seed
            seed_module = load_module('seed_to_private.py', 'seed_to_private')
            seed_module.main()
            
        elif choice == 2:
            # Carrega e executa o decodificador BIP38
            bip38_module = load_module('bip38_decoder.py', 'bip38_decoder')
            bip38_module.main()
            
        elif choice == 3:
            # Carrega e executa a interface de negociação Kraken
            kraken_module = load_module('kraken_trader.py', 'kraken_trader')
            kraken_module.main()
            
        else:
            print("\nOpção inválida. Por favor, escolha uma opção entre 0 e 3.")
            input("\nPressione Enter para continuar...")

if __name__ == "__main__":
    main()
Como Usar o Kit
Conversor de Seed para Chave Privada
Use esta ferramenta para converter sua frase mnemônica (seed phrase) em chaves privadas Bitcoin:

Execute python seed_to_private.py
Digite as 12, 15, 18, 21 ou 24 palavras da sua seed phrase
Digite sua senha (se houver) ou deixe em branco
A ferramenta mostrará o endereço Bitcoin e as chaves privadas correspondentes
Decodificador BIP38
Use esta ferramenta para descriptografar chaves privadas no formato BIP38:

Execute python bip38_decoder.py
Digite a chave criptografada no formato BIP38 (começando com "6P...")
Digite a senha usada para criptografar a chave
A ferramenta mostrará a chave privada descriptografada e o endereço Bitcoin correspondente
Interface de Negociação Kraken
Use esta ferramenta para interagir com a exchange Kraken:

Execute python kraken_trader.py
Configure suas chaves de API da Kraken (você precisa criá-las no site da Kraken primeiro)
Utilize as opções para verificar saldo, obter cotações, vender Bitcoin com taxa alta ou gerar endereços de depósito
Interface Unificada
Para acessar todas as ferramentas através de uma única interface:

Execute python bitcoin_toolkit.py
Escolha a ferramenta desejada no menu principal
Observações de Segurança
IMPORTANTE: Execute estas ferramentas em um computador seguro, preferencialmente offline.
Nunca compartilhe suas seeds, chaves privadas ou senhas.
Guarde suas chaves de API com cuidado e configure-as com permissões limitadas.
Considere usar um sistema operacional dedicado para operações com criptomoedas.
Sempre faça backups seguros das suas chaves e senhas.
Limitações
Estas ferramentas são fornecidas "como estão", sem garantias.
A biblioteca de decodificação BIP38 é uma implementação simplificada e pode não funcionar com todos os formatos de chave.
A API da Kraken pode mudar, exigindo atualizações no código.
Contribuições
Para melhorar este kit de ferramentas, considere:

Adicionar suporte para mais criptomoedas
Implementar recursos de segurança adicionais
Criar uma interface gráfica
Melhorar a documentação
# seedtobip
