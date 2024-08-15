#criar um codigo para criptografar senhas
import tkinter
from tkinter import messagebox
from cryptography.fernet import Fernet
import hashlib
import rsa
#criptografar para md5, hash, sha255, fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def fernet(senha):
    chave = Fernet.generate_key()
    f = Fernet(chave) 
    criptografado = f.encrypt(senha)
    descriptografado = f.decrypt(criptografado)
    return criptografado

def hash(senha):
    s = hashlib.sha256(senha).hexdigest()
    return s

def sha_256(senha):
    # O SHA-256 permite que você criptografe uma senha porem não ha como desencriptografar
    # Uma vez encriptografada, é irreversível
    s = hashlib.sha256(senha)
    return s.hexdigest()

def sha_512(senha):
    print('O SHA-256 permite que você criptografe uma senha porem não ha como desencriptografar')
    print('Uma vez encriptografada, é irreversível')
    s = hashlib.sha512(senha)
    return s.hexdigest()

def sha_224(senha):
    # O SHA-256 permite que você criptografe uma senha porem não ha como desencriptografar
    # Uma vez encriptografada, é irreversível
    cript = hashlib.sha224(senha)
    return cript.hexdigest()

def criptografia_rsa(senha):
    # Esse é um tipo de criptografia assimetrica, ou seja, gera uma chave publica e uma privada
    # A pública criptografa e a privada descriptografa
    public_key, private_key = rsa.newkeys(512)
    #criptografando a senha
    criptografar = rsa.encrypt(senha, public_key)
    # descriptografando a senha
    descriptografar = rsa.decrypt(criptografar, private_key)
    return criptografar.hex()


def encrypt_aes(senha):
    key = os.urandom(32)
    #senha = 'A Revolução dos anônimos'.encode()
    # Gerar um vetor de inicialização (IV) aleatório
    iv = os.urandom(16)

    # Criar um objeto de cifra usando o algoritmo AES em modo CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Adicionar padding aos dados para que tenham um tamanho múltiplo de 16 bytes (tamanho do bloco do AES)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(senha) + padder.finalize()

    # Criptografar os dados
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Retornar o IV concatenado com o texto cifrado
    resultado = iv + ciphertext
    return resultado.hex()

def Botao_pressionado():
    # quando o botao for pressionado, verificar
    # se o usuario digitou uma senha
    # se o usuario escolheu uma criptografia
    escolher_criptografia = False
    digito_senha = False
    #se der tudo certo, vai enviar confirmacao como True para a outra funcao
    confirmacao = False
    tamanho = len(senha.get())  # verifica se o campo senha esta vazio
    valor_cript = valor.get()   # tipo de criptografia
    if valor_cript != 'escolha' :
        escolher_criptografia = True
    else:
        messagebox.showerror('Erro', 'Escolha um tipo de criptografia antes de continuar')
    if tamanho != 0:
        digito_senha = True
    else:
        messagebox.showerror('Erro', 'Digite uma senha antes de continuar')
    if escolher_criptografia and digito_senha:
        Escrever_Text(confirmacao,valor_cript, senha.get())



def Escrever_Text(confirmacao, tipo_cript, senha):
    #essa funcao vai escrever na caixa de text
    caixa_text.config(state='normal')
    valor_cript = valor.get()
    if tipo_cript == 'AES':
        r = encrypt_aes(senha.encode())
        caixa_text.insert(1.0, r)
    elif tipo_cript == 'RSA':
        r = criptografia_rsa(senha.encode())
        caixa_text.insert(1.0, r)
    elif tipo_cript == 'SHA512':
        r = sha_512(senha.encode())
        caixa_text.insert(1.0, r)
    elif tipo_cript == 'FERNET':
        r = fernet(senha.encode())
        caixa_text.insert(1.0, r)
    elif tipo_cript == 'SHA224':
        r = sha_224(senha.encode())
        caixa_text.insert(1.0, r)
    elif tipo_cript == 'SHA256':
        r = sha_256(senha.encode())
        caixa_text.insert(1.0, r)
    caixa_text.config(state='disabled')

def Limpar():
    #limpar campo Text
    caixa_text.config(state='normal')
    caixa_text.delete(1.0, tkinter.END)
    caixa_text.config(state='disabled')



#criando interface para o codigo
#janela
janela = tkinter.Tk()
janela.title('Cipher')
janela.config(background='blue')
janela.geometry('500x400')
cor_fundo = 'blue'
janela.maxsize(500,400)
janela.minsize(500,400)
#adicionando o texto do titulo na janela
titulo = tkinter.Label(janela, text='Cipher', font=('Impact', 20), background=cor_fundo, foreground='white')
titulo.place(x=200, y=1)

#criando o label da senha
texto_senha = tkinter.Label(janela, text='Insira a senha ', bg=cor_fundo, font=('Arial', 18), foreground='white')
texto_senha.place(x=2, y=50)

#solicitar a senha do usuario
senha = tkinter.Entry(janela, width=40, font=('Calibri', 16))
senha.place(x=160, y=50)

#caixa para usuario escolher qual tipo de criptografia ele vai usar
options = ['AES', 'SHA256', 'SHA512','SHA224' ,'FERNET']
valor = tkinter.StringVar(janela)
valor.set('Selecione')
tipo_criptografia = tkinter.OptionMenu(janela, valor, *options)
tipo_criptografia.config(height=1, width=10)
tipo_criptografia.place(x=20,y=105)

#botao que vai criptografar a senha
botao = tkinter.Button(janela, text='Criptografar', font=('Calibri', 14), background='black', bg='white', command=Botao_pressionado)
botao.place(x=180, y=100)

#botao de limpar campo Text
limpar_text = tkinter.Button(janela, text='Limpar', font=('Calibri', 14), background='black', bg='white', command=Limpar)
limpar_text.place(x=350, y=100)

#campo onde a senha criptografada vai aparecer
caixa_text = tkinter.Text(janela, width=61, height=14)
caixa_text.config(state='disabled')
caixa_text.place(x=3, y=160)
janela.mainloop()
