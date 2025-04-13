# bitcoin_toolkit.py
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
