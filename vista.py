from fastapi import FastAPI, Depends, HTTPException, Form, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
from models import User,Product, Cart, DetailsCart, OrderDetail ,Order,Payment,Class,ClassReservation,OrderStatus,Publication
from schemas import ReservationClass,UserCreate, UserLogin, CarritoAgregar, CarritoResponseModel, Usuario, UpdateRequest, UpdatePassword, ForgotPasswordRequest, ResetPasswordRequest,mural,PayClass
from security import hash_password, verify_password, create_access_token,verify_token
from fastapi.staticfiles import StaticFiles
import os
import json
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from email.mime.text import MIMEText 
import base64 
from googleapiclient.discovery import build 
from datetime import time,timedelta
from fastapi.responses import RedirectResponse
from typing import List
from sqlalchemy import or_
from urllib.parse import quote
from sqlalchemy import func
from dotenv import load_dotenv
import cloudinary.uploader
from cloudinary_config import cloudinary



app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "https://arqitectura-limpia-production.up.railway.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()






SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/gmail.send" 
]
REDIRECT_URI = "http://localhost:8000/auth/callback"

#Iniciar Flujo
# Recuperar el JSON desde la variable de entorno
credentials_json = os.getenv("GOOGLE_CREDENTIALS_JSON")
print(credentials_json)
if not credentials_json:
    raise RuntimeError("GOOGLE_CREDENTIALS_JSON no está configurado")

# Convertir el JSON a un diccionario
client_secrets = json.loads(credentials_json)

# Crear el flujo de OAuth
# El flow nos permite crear url de autorizacion y cambiar tokens
flow = Flow.from_client_config( 
    client_secrets,
    scopes=SCOPES,
    redirect_uri=REDIRECT_URI
)


def send_email(tu_email: str, subject: str, body: str):
    try:
        # Cargar las credenciales desde el archivo
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)

        # Crear el mensaje
        message = MIMEText(body, "html")
        message["to"] = tu_email
        message["subject"] = subject
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode("utf-8")

        # Enviar el correo usando la API de Gmail
        service = build("gmail", "v1", credentials=creds)
        service.users().messages().send(
            userId="me",
            body={"raw": raw_message}
        ).execute()
        return True
    except Exception as e:
        print(f"Error al enviar el correo: {e}")
        return False



@app.post("/forgot-password")
async def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == request.email).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    reset_token = create_access_token(data={"sub": db_user.email}, expires_delta=timedelta(minutes=15))
    reset_link = f"http://localhost:8080/reset-password?token={reset_token}"

    email_body = f"""
        <h1>Recuperación de contraseña</h1>
        <p>Haz clic en el siguiente enlace para restablecer tu contraseña:</p>
        <a href="{reset_link}">Restablecer contraseña</a>
        <p>Este enlace expirará en 15 minutos.</p>
    """

    if send_email(db_user.email, "Recuperación de contraseña", email_body):
        return {"message": "Se ha enviado un correo con instrucciones para restablecer tu contraseña."}
    else:
        raise HTTPException(status_code=500, detail="Error al enviar el correo")

@app.post("/reset-password")
async def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):

    payload = verify_token(request.token)  
    if not payload:
        raise HTTPException(status_code=400, detail="Token inválido o expirado")

    db_user = db.query(User).filter(User.email == payload["sub"]).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    db_user.password = hash_password(request.new_password)  
    db.commit()

    return {"message": "Contraseña actualizada correctamente"}


@app.get("/auth/callback")
async def callback(code: str, db: Session = Depends(get_db)):
    try:
        flow.fetch_token(code=code)
        credentials = flow.credentials

        user_info_service = build("oauth2", "v2", credentials=credentials)
        user_info = user_info_service.userinfo().get().execute()
        
        email = user_info["email"]
        nombre = user_info.get("name", "Usuario")

        db_user = db.query(User).filter(User.email == email).first()

        if not db_user:
            new_user = User(email=email, nombre=nombre, rol="cliente")
            db.add(new_user)
            db.commit()
            db.refresh(new_user)

        access_token = create_access_token(data={"sub": email, "rol": "cliente"})
        
        # Redirige a una ruta especial que maneje el token (ej: /auth-callback en frontend)
        token_encoded = quote(access_token)  # Codifica el token para la URL
        return RedirectResponse(url=f"http://localhost:8080/auth-callback?token={token_encoded}")

    except Exception as e:
        print(f"Error en el callback: {e}")
        return RedirectResponse(url="http://localhost:8080/register")

@app.get("/auth/login")
async def login():
    authorization_url, state = flow.authorization_url(prompt="consent")
    return RedirectResponse(authorization_url)


    
@app.post("/register")
async def register(user_data: UserCreate, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == user_data.email).first()
    if user:
        raise HTTPException(status_code=400, detail="El correo ya está registrado")
    
    if not user_data.password:
        raise HTTPException(status_code=400, detail="La contraseña es obligatoria")
    
    hashed_password = hash_password(user_data.password)
    new_user = User(
        nombre=user_data.nombre,
        email=user_data.email,
        telefono=user_data.telefono,
        password=hashed_password,
        rol=user_data.rol
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "Usuario registrado correctamente"}



@app.post("/login")
async def login(user_data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == user_data.email).first()
    if user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if not verify_password(user_data.password, user.password):
        raise HTTPException(status_code=400, detail="Contraseña Incorrecta")

    token = create_access_token({"sub": user.email, "email": user.email, "rol": user.rol.name})
    return {"access_token": token, "token_type": "bearer", "email": user.email, "rol": user.rol.name}



@app.get("/usuarios", response_model=Usuario)  
async def obtener_usuario(token: str = Depends(verify_token), db: Session = Depends(get_db)):
    email_user = token.get("sub") 
    if not email_user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")  
    db_user = db.query(User).filter(User.email == email_user).first()  
    if db_user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado en la base de datos") 
    
    return db_user 

@app.put("/usuarios/{campo}/{email}")
async def update_user_data(campo: str,email: str,data: UpdateRequest, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == email).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado en la base de datos")

    if campo not in ['nombre','email', 'telefono', ]:
        raise HTTPException(status_code=400, detail="Campo no válido")

    if campo == 'email':
        db_user.email = data.value
    elif campo == 'telefono':
        db_user.telefono = data.value
    elif campo == 'nombre':
        db_user.nombre = data.value
    elif campo == 'rol':
        db_user.rol = data.value

    db.commit()
    db.refresh(db_user)

    return {"message": f"{campo.capitalize()} actualizado exitosamente", "user": db_user}


@app.get("/todousuarios", response_model=List[Usuario])  
async def obtener_usuario(token: str = Depends(verify_token), db: Session = Depends(get_db)):
    usuarios = db.query(User).all()
    if not usuarios:
        raise HTTPException(status_code=404, detail="No hay usuarios en la base de datos")
    return usuarios


@app.put("/password/")
async def update_password(data: UpdatePassword, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == data.email).first()
    if not db_user:
        raise HTTPException(status_code=400, detail="El correo no está registrado")  
    
    if verify_password(data.original, db_user.password):  # Verifica la contraseña actual
        db_user.password = hash_password(data.nuevo)  # Hashea la nueva contraseña
        
        db.commit()
        db.refresh(db_user)
        
        return {"message": "Contraseña actualizada exitosamente"}
    else:
        raise HTTPException(status_code=400, detail="La contraseña original no es correcta")






app.mount("/images", StaticFiles(directory="img"), name="images")

@app.get("/mostrarimagenes")
def obtener_imagenes(limit: int = 10, offset: int = 0, db: Session = Depends(get_db)):
    productos = (
        db.query(Product)
        .filter(Product.activo == True)
        .order_by(func.rand()) 
        .offset(offset)
        .limit(limit)
        .all()
    )
    
    return [
        {
            "id": producto.id,
            "nombre": producto.nombre,
            "descripcion": producto.descripcion,
            "precio": producto.precio,
            "tipo_unidad": producto.tipo_unidad,
            "color": producto.color,
            "category": producto.category,
            "imagen_url": producto.imagen_url  # No es necesario concatenar con localhost
        }
        for producto in productos
    ]


@app.get("/mostrarimagenes_Categoria/{category}")
def obtener_imagenes(category: str, limit: int = 10, offset: int = 0, db: Session = Depends(get_db)):
    productos = db.query(Product).filter(Product.category == category and Product.activo == True).offset(offset).limit(limit).all()
    return [
        {
            "id": producto.id,
            "nombre": producto.nombre,
            "descripcion": producto.descripcion,
            "precio": producto.precio,
            "tipo_unidad": producto.tipo_unidad,
            "color": producto.color,
            "category": producto.category,
            "imagen_url":producto.imagen_url 
        }
        for producto in productos
    ]



@app.get("/buscar_producto/{id}")
def obtener_imagenes(id: int, db: Session = Depends(get_db)):
    producto = db.query(Product).filter(Product.id == id and Product.activo == True).first()
    if producto:  
        return {
            "id": producto.id,
            "nombre": producto.nombre,
            "descripcion": producto.descripcion,
            "precio": producto.precio,
            "tipo_unidad": producto.tipo_unidad,
            "color": producto.color,
            "category": producto.category,
            "imagen_url": producto.imagen_url 
        }
    else:
        return {"error": "Producto no encontrado"}, 404




@app.get("/ver_carrito/{email}", response_model=list[CarritoResponseModel])
def ver_carrito(email: str, session: Session = Depends(get_db)):
    cliente = session.query(User).filter(User.email == email).first()
    
    if not cliente:
        raise HTTPException(status_code=404, detail="El cliente no existe")
    
    carrito = session.query(DetailsCart).join(Cart).filter(Cart.cliente_id == cliente.id).all()

    if not carrito:
        raise HTTPException(status_code=404, detail="El carrito está vacío")

    carrito_respuesta = []
    for item in carrito:
        producto = session.query(Product).filter_by(id=item.producto_id).first()
        if producto:
            carrito_respuesta.append({
                "product_id": item.producto_id,
                "product_name": producto.nombre,
                "cantidad": item.cantidad,
                "precio": producto.precio,
                "total": producto.precio * item.cantidad,
                "imagen_url": producto.imagen_url   # Añadir URL completa para la imagen
            })
    
    return carrito_respuesta

@app.post("/agregar_al_carrito/{email_cliente}")
def agregar_al_carrito(carrito_data: CarritoAgregar, email_cliente: str, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == email_cliente).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado en la base de datos")

    carrito = db.query(Cart).filter_by(cliente_id=db_user.id).first()
    if carrito is None:
        carrito = Cart(cliente_id=db_user.id)
        db.add(carrito)
        db.commit()
        db.refresh(carrito) 

    detalle_existente = db.query(DetailsCart).filter_by(carrito_id=carrito.id, producto_id=carrito_data.producto_id).first()

    if detalle_existente:
        detalle_existente.cantidad += carrito_data.cantidad
        message = f'Cantidad actualizada del producto {carrito_data.producto_id} en el carrito para el cliente {db_user.id}'
    else:
        nuevo_detalle = DetailsCart(
            carrito_id=carrito.id,
            producto_id=carrito_data.producto_id,
            cantidad=carrito_data.cantidad
        )
        db.add(nuevo_detalle)
        message = f'Producto {carrito_data.producto_id} agregado al carrito para el cliente {db_user.id}'

    db.commit()

    return {"message": message}

@app.put("/actualizar_producto_carrito/{email_cliente}")
def actualizar_producto_carrito(email_cliente: str,producto_data: CarritoAgregar, db: Session = Depends(get_db)
):
    db_user = db.query(User).filter(User.email == email_cliente).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado en la base de datos")

    carrito = db.query(Cart).filter_by(cliente_id=db_user.id).first()
    if carrito is None:
        raise HTTPException(status_code=404, detail="Carrito no encontrado para el usuario")

    detalle_existente = db.query(DetailsCart).filter_by(
        carrito_id=carrito.id,
        producto_id=producto_data.producto_id
    ).first()

    if detalle_existente is None:
        raise HTTPException(status_code=404, detail="Producto no encontrado en el carrito")

    detalle_existente.cantidad = producto_data.cantidad
    db.commit()

    return {
        "message": f"Cantidad del producto {producto_data.producto_id} actualizada a {producto_data.cantidad}"
    }



@app.delete("/eliminar_del_carrito/{email_cliente}/{producto_id}")
def eliminar_del_carrito(email_cliente: str, producto_id: int, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == email_cliente).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado en la base de datos")

    carrito = db.query(Cart).filter_by(cliente_id=db_user.id).first()
    if carrito is None:
        raise HTTPException(status_code=404, detail="Carrito no encontrado para el usuario")

    detalle_existente = db.query(DetailsCart).filter_by(carrito_id=carrito.id, producto_id=producto_id).first()
    if detalle_existente is None:
        raise HTTPException(status_code=404, detail="Producto no encontrado en el carrito")

    db.delete(detalle_existente)
    db.commit()

    detalles_restantes = db.query(DetailsCart).filter_by(carrito_id=carrito.id).count()
    if detalles_restantes == 0:
        db.delete(carrito)
        db.commit()
        return {"message": f"Producto {producto_id} eliminado y carrito vacío eliminado para el cliente {db_user.id}"}

    return {"message": f"Producto {producto_id} eliminado del carrito para el cliente {db_user.id}"}





@app.get("/informacionTabla")
def obtener_imagenes(db: Session = Depends(get_db)):
    productos = db.query(Product).all()
    return [
        {
            "id": producto.id,
            "nombre": producto.nombre,
            "descripcion": producto.descripcion,
            "precio": producto.precio,
            "tipo_unidad": producto.tipo_unidad,
            "color": producto.color,
            "category": producto.category,
            "activo" : producto.activo,
            "imagen_url": producto.imagen_url 
        }
        for producto in productos
    ]


@app.get("/informacionTabla/{category}")
def obtener_imagenes(category: str, db: Session = Depends(get_db)):
    productos = db.query(Product).filter(Product.category == category).all()
    return [
        {
          "id": producto.id,
            "nombre": producto.nombre,
            "descripcion": producto.descripcion,
            "precio": producto.precio,
            "tipo_unidad": producto.tipo_unidad,
            "color": producto.color,
            "category": producto.category,
            "activo" : producto.activo,
            "imagen_url": producto.imagen_url 
        }
        for producto in productos
    ]

@app.get("/informacionTablaNombre/{nombre}")
def obtener_imagenes(nombre: str, db: Session = Depends(get_db)):
    producto = db.query(Product).filter(Product.nombre.ilike(nombre) ).first()
    
    if not producto:
        raise HTTPException(status_code=404, detail="Producto no encontrado")
    
    return {
         "id": producto.id,
            "nombre": producto.nombre,
            "descripcion": producto.descripcion,
            "precio": producto.precio,
            "tipo_unidad": producto.tipo_unidad,
            "color": producto.color,
            "category": producto.category,
            "activo" : producto.activo,
            "imagen_url": producto.imagen_url 
    }


@app.post("/insertardos")
async def registrar_producto(
    nombre: str = Form(...),
    descripcion: str = Form(...),
    precio: float = Form(...),
    tipo_unidad: str = Form(...),
    color: str = Form(...),
    category: str = Form(...),
    url: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    # Verificar el tipo de archivo
    if url.content_type not in ["image/jpeg", "image/png"]:
        raise HTTPException(status_code=400, detail="Formato de archivo no soportado")

    # Verificar si el producto ya existe
    existing_product = db.query(Product).filter(Product.nombre == nombre, Product.color == color).first()
    if existing_product:
        raise HTTPException(status_code=400, detail="Ya existe un producto con el mismo nombre y color")

    # Leer los datos de la imagen
    image_data = await url.read()  # Leer los datos de la imagen desde la solicitud

    # Subir la imagen a Cloudinary
    result = cloudinary.uploader.upload(image_data, folder="productos")

    # Obtener la URL de la imagen subida
    imagen_url = result["secure_url"]

    # Crear el objeto de producto
    producto_data = Product(
        nombre=nombre,
        descripcion=descripcion,
        precio=precio,
        tipo_unidad=tipo_unidad,
        color=color,
        category=category,
        imagen_url=imagen_url
    )

    # Guardar el producto en la base de datos
    db.add(producto_data)
    db.commit()
    db.refresh(producto_data)

    # Responder con la información del producto registrado
    return {
        "status": "Producto registrado exitosamente",
        "data": {
            "nombre": producto_data.nombre,
            "descripcion": producto_data.descripcion,
            "precio": producto_data.precio,
            "tipo_unidad": producto_data.tipo_unidad,
            "color": producto_data.color,
            "category": producto_data.category,
            "imagen_url": imagen_url
        }
    }



@app.put("/productosActualizar/{product_id}")
async def actualizar_producto(
    product_id: int,
    nombre: str = Form(None),
    descripcion: str = Form(None),
    precio: float = Form(None),
    tipo_unidad: str = Form(None),
    color: str = Form(None),
    category: str = Form(None),
    url: UploadFile = File(None),
    db: Session = Depends(get_db)
):
    # Buscar el producto a actualizar
    producto_data = db.query(Product).filter(Product.id == product_id).first()
    if not producto_data:
        raise HTTPException(status_code=404, detail="Producto no encontrado")

    # Verificar si ya existe otro producto con el mismo nombre y color (excepto el actual)
    existing_product = db.query(Product).filter(Product.nombre == nombre, Product.color == color).filter(Product.id != product_id).first()
    if existing_product:
        raise HTTPException(status_code=400, detail="Ya existe un producto con el mismo nombre y color")

    # Actualizar los campos si no son None
    if nombre is not None:
        producto_data.nombre = nombre
    if descripcion is not None:
        producto_data.descripcion = descripcion
    if precio is not None:
        producto_data.precio = precio
    if tipo_unidad is not None:
        producto_data.tipo_unidad = tipo_unidad
    if color is not None:
        producto_data.color = color
    if category is not None:
        producto_data.category = category

    # Si se sube una nueva imagen, actualizarla
    if url:
        # Verificar el tipo de archivo de la imagen
        if url.content_type not in ["image/jpeg", "image/png"]:
            raise HTTPException(status_code=400, detail="Formato de archivo no soportado")

        # Leer los datos de la imagen
        image_data = await url.read()

        # Subir la imagen a Cloudinary
        result = cloudinary.uploader.upload(image_data, folder="productos")

        # Obtener la URL de la imagen subida
        imagen_url = result["secure_url"]

        # Actualizar la URL de la imagen
        producto_data.imagen_url = imagen_url

    # Guardar los cambios en la base de datos
    db.commit()
    db.refresh(producto_data)

    return {"status": "Producto actualizado exitosamente", "data": {
        "nombre": producto_data.nombre,
        "descripcion": producto_data.descripcion,
        "precio": producto_data.precio,
        "tipo_unidad": producto_data.tipo_unidad,
        "color": producto_data.color,
        "category": producto_data.category,
        "imagen_url": producto_data.imagen_url
    }}



@app.delete("/productosEliminar/{product_id}")
async def eliminar_producto(product_id: int, db: Session = Depends(get_db)):
    producto_data = db.query(Product).filter(Product.id == product_id).first()
    if not producto_data:
        raise HTTPException(status_code=404, detail="Producto no encontrado")
    db.delete(producto_data)
    db.commit()

    return {"status": "Producto eliminado exitosamente", "product_id": product_id}


@app.delete("/productos/{producto_id}", response_model=dict)
async def eliminar_producto(producto_id: int, db: Session = Depends(get_db)):
    producto = db.query(Product).filter(Product.id == producto_id).first()
    if not producto:
        raise HTTPException(status_code=404, detail="Producto no encontrado")

    producto.activo = False
    db.commit()
    db.refresh(producto)

    return {"detail": "Producto desactivado correctamente"}

@app.put("/productos/desactivar/{producto_id}", response_model=dict)
def desactivar_producto(producto_id: int, db: Session = Depends(get_db)):
    producto = db.query(Product).filter(Product.id == producto_id).first()

    if not producto:
        raise HTTPException(status_code=404, detail="Producto no encontrado")

    producto.activo = False
    db.commit()
    db.refresh(producto)

    return {"detail": "Producto desactivado correctamente"}


@app.put("/estado_producto/{accion}/{producto_id}", response_model=dict)
def estado_producto(accion: str, producto_id: int, db: Session = Depends(get_db)):
    producto = db.query(Product).filter(Product.id == producto_id).first()

    if not producto:
        raise HTTPException(status_code=404, detail="Producto no encontrado")

    if accion == "activar":
        producto.activo = True
    elif accion == "desactivar":
        producto.activo = False
    else:
        raise HTTPException(status_code=400, detail="Acción inválida. Usa 'activar' o 'desactivar'.")

    db.commit()
    db.refresh(producto)

    return {"detail": f"Producto {accion} correctamente"}


@app.delete("/productos/{producto_id}", response_model=dict)
async def eliminar_producto(producto_id: int, db: Session = Depends(get_db)):
    producto = db.query(Product).filter(Product.id == producto_id).first()
    
    if not producto:
        raise HTTPException(status_code=404, detail="Producto no encontrado")

    if not producto:
        raise HTTPException(status_code=404, detail="Producto no encontrado")

    producto.activo = False
    db.commit()
    db.refresh(producto)

    return {"detail": "Producto desactivado correctamente"}


@app.post("/realizar_pedido/{email_cliente}/{metodo_pago}")
def realizar_pedido(email_cliente: str, metodo_pago: str, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == email_cliente).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado en la base de datos")

    carrito = db.query(Cart).filter_by(cliente_id=db_user.id).first()
    if carrito is None:
        raise HTTPException(status_code=404, detail="No hay productos en el carrito para procesar el pedido")
    detalles_carrito = db.query(DetailsCart).filter_by(carrito_id=carrito.id).all()
    if not detalles_carrito:
        raise HTTPException(status_code=404, detail="El carrito está vacío")

    if metodo_pago == "NEQUI" or metodo_pago == "TARJETA":
        nuevo_pedido = Order(cliente_id=db_user.id, estado='paid')
    elif metodo_pago == "PRESENCIAL":
        nuevo_pedido = Order(cliente_id=db_user.id, estado='reserved')
    else:
        raise HTTPException(status_code=400, detail="Método de pago no válido")

    db.add(nuevo_pedido)
    db.commit()
    db.refresh(nuevo_pedido)  

    for detalle in detalles_carrito:
        detalle_pedido = OrderDetail(
            pedido_id=nuevo_pedido.id,
            producto_id=detalle.producto_id,
            cantidad=detalle.cantidad,
            precio_unitario=detalle.product.precio  
        )
        db.add(detalle_pedido)

    monto_total = sum(detalle.cantidad * detalle.product.precio for detalle in detalles_carrito)

    nuevo_pago = Payment(
        pedido_id=nuevo_pedido.id,
        metodo_pago=metodo_pago, 
        monto=monto_total
    )
    db.add(nuevo_pago)

    db.query(DetailsCart).filter_by(carrito_id=carrito.id).delete()

    db.commit()

    return {
        "message": f"Pedido realizado exitosamente con ID {nuevo_pedido.id}",
        "monto_total": monto_total,
        "estado_pedido": nuevo_pedido.estado,
        "id": nuevo_pedido.id  
    }


@app.get("/historialCompra")
async def historalCompra(token: str = Depends(verify_token), db: Session = Depends(get_db)):
    email_user = token.get("sub")
    if not email_user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")  
    
    db_user = db.query(User).filter(User.email == email_user).first() 
    if db_user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado en la base de datos")

    datos = db.query(Payment, Order, User, OrderDetail, Product) \
        .join(Order, Order.id == Payment.pedido_id) \
        .join(OrderDetail, OrderDetail.pedido_id == Order.id) \
        .join(Product, Product.id == OrderDetail.producto_id) \
        .join(User, User.id == Order.cliente_id) \
        .filter(User.email == email_user) \
        .all()

    pedidos_dict = {}
    for payment, order, user, order_detail, product in datos:
        pedido_id = payment.pedido_id
        if pedido_id not in pedidos_dict: 
            pedidos_dict[pedido_id] = {
                "pedido_id": pedido_id,
                "comprador": user.nombre,
                "email": user.email,
                "telefono": user.telefono,
                "fecha_pedido": order.fecha_pedido.date() if order.fecha_pedido else None,
                "metodo_pago": payment.metodo_pago,
                "monto": payment.monto,
                "estado_pedido": order.estado,
                "fecha_pago": payment.fecha_pago.date(),
                "productos": []
            }
        pedidos_dict[pedido_id]["productos"].append({
            "producto_nombre": product.nombre,
            "categoria": product.categoria if hasattr(product, "categoria") else "N/A",
            "imagen": product.imagen if hasattr(product, "imagen") else "",
            "cantidad": order_detail.cantidad,
            "precio_unitario": order_detail.precio_unitario,
            "total_producto": order_detail.cantidad * order_detail.precio_unitario
        })

    pedidos_list = list(pedidos_dict.values())
    pedidos_list_sorted = sorted(pedidos_list, key=lambda x: x["pedido_id"])

    return pedidos_list_sorted



@app.get("/InventarioPay")
async def mostrar_InventarioPay(db: Session = Depends(get_db)):
    datos = db.query(Payment, Order, User, OrderDetail, Product) \
        .join(Order, Order.id == Payment.pedido_id) \
        .join(OrderDetail, OrderDetail.pedido_id == Order.id) \
        .join(Product, Product.id == OrderDetail.producto_id) \
        .join(User, User.id == Order.cliente_id) \
        .all()

    pedidos_dict = {}
    for payment, order, user, order_detail, product in datos:
        pedido_id = payment.pedido_id
        if pedido_id not in pedidos_dict: 
            pedidos_dict[pedido_id] = {
                "pedido_id": pedido_id,
                "comprador": user.nombre,
                "correo": user.email,
                "metodo_pago": payment.metodo_pago,
                "monto": payment.monto,
                "estado_pedido": order.estado,
                "fecha_pago": payment.fecha_pago.date(),
                "productos": []
            }
        pedidos_dict[pedido_id]["productos"].append({
            "producto_nombre": product.nombre,
            "cantidad": order_detail.cantidad,
            "precio_unitario": order_detail.precio_unitario,
            "total_producto": order_detail.cantidad * order_detail.precio_unitario

        })

    pedidos_list = list(pedidos_dict.values())
    pedidos_list_sorted = sorted(pedidos_list, key=lambda x: x["pedido_id"])

    return pedidos_list_sorted


#GESTION DE CLASES========================================================================================================

#Todas las clases
@app.get("/allClass")
async def consultDatesClass(db: Session = Depends(get_db)):
    allClass = db.query(Class).all()
    return [
        {
            "id":Class.id,
            "titulo": Class.titulo,
            "descripcion": Class.descripcion,
            "profesor": Class.profesor,
            "fecha": Class.fecha,  
            "comienzo": Class.comienzo,
            "final": Class.final,
            "precio": Class.precio,
            "habilitado":Class.habilitado,
            "imagen": f"http://localhost:8000{Class.imagen}"
        }
        for Class in allClass
    ]



# Insertar clase
@app.post("/insertClass/")
async def insert_class(
    titulo:str=Form(...),
    descripcion:str=Form(...),
    profesor: str = Form(...), 
    fecha: str = Form(...), 
    comienzo:time = Form(...), 
    final:time = Form(...), 
    precio:float = Form(...), 
    imagen:UploadFile = File(...),
    db: Session = Depends(get_db)):
    existing_class = db.query(Class).filter(Class.titulo == titulo).first()
    if existing_class:
        raise HTTPException(status_code=400, detail="La clase ya está registrada")
    
    # Ruta de guardado del archivo
    folder_path = "img"
    file_location = os.path.join(folder_path, imagen.filename)
    
    
    # Guardar el archivo en el servidor
    with open(file_location, "wb") as buffer:
        buffer.write(await imagen.read())

    # Crear una URL accesible para la imagen
    img = f"/images/{imagen.filename}"
    
    new_class = Class(
        titulo = titulo,
        descripcion = descripcion,
        profesor = profesor,
        fecha = fecha,
        comienzo = comienzo,
        final = final,
        precio = precio,
        imagen = img
    )
    
    db.add(new_class)
    db.commit()
    db.refresh(new_class)
    return new_class

# Editar clase
@app.put("/editClass/{titulo}")
async def edit_class(
    titulo: str,
    new_titulo: str = Form(...),
    descripcion: str = Form(...),
    profesor: str = Form(...),
    fecha: str = Form(...),
    comienzo: str = Form(...),
    final: str = Form(...),
    precio: float = Form(...),
    imagen: UploadFile = File(None),  # Imagen opcional
    db: Session = Depends(get_db)
):
    # Buscar la clase en la base de datos por título
    existing_class = db.query(Class).filter(Class.titulo == titulo).first()
    
    if not existing_class:
        raise HTTPException(status_code=404, detail="Clase no registrada")

    # Verificar si ya existe una clase con el nuevo título proporcionado
    repit_class = db.query(Class).filter(Class.titulo == new_titulo).first()
    if repit_class and repit_class.id != existing_class.id:
        raise HTTPException(status_code=400, detail="Clase ya registrada con ese título")
    
    # Actualizar campos de texto
    existing_class.titulo = new_titulo
    existing_class.descripcion = descripcion
    existing_class.profesor = profesor
    existing_class.fecha = fecha
    existing_class.comienzo = comienzo
    existing_class.final = final
    existing_class.precio = precio

    # Si se proporciona una nueva imagen, procesarla
    if imagen:
        # Validar el tipo de archivo
        if imagen.content_type not in ["image/jpeg", "image/png"]:
            raise HTTPException(status_code=400, detail="Formato de archivo no soportado")

        # Ruta de guardado del archivo
        folder_path = "img"
        file_location = os.path.join(folder_path, imagen.filename)
        
        # Crear la carpeta si no existe
        os.makedirs(folder_path, exist_ok=True)

        # Guardar el archivo en el servidor
        with open(file_location, "wb") as buffer:
            buffer.write(await imagen.read())

        # Crear una URL accesible para la nueva imagen
        existing_class.imagen = f"/images/{imagen.filename}"

    # Guardar los cambios en la base de datos
    db.commit()
    db.refresh(existing_class)

    # Respuesta con la información actualizada de la clase
    return existing_class

# Cambiar estado de habilitar/deshabilitar clase
@app.put("/editHability/{title}/{hability}")
async def edit_hability(title: str, hability: bool, db: Session = Depends(get_db)):
    existing_class = db.query(Class).filter(Class.id == title).first()

    if not existing_class:
        raise HTTPException(status_code=404, detail="Clase no encontrada")

    existing_class.habilitado = hability
    db.commit()
    db.refresh(existing_class)

    return existing_class

# Eliminar clase
@app.delete("/deleteClass/{title}")
async def delete_class(title: int, db: Session = Depends(get_db)):
    existing_class = db.query(Class).filter(Class.id == title).first()

    if not existing_class:
        raise HTTPException(status_code=404, detail="Clase no encontrada")

    # Actualizar el estado de las reservas en lugar de eliminarlas
    db.query(ClassReservation).filter(
        ClassReservation.id_clase == title,
        or_(ClassReservation.estado == "paid", ClassReservation.estado == "cancelled")
    ).update({"estado": "cancelled"}, synchronize_session=False)

    # Ahora eliminar la clase
    db.delete(existing_class)
    db.commit()

    return {"message": "Clase eliminada"}

#Reservaciones
@app.get("/Reservations/")
async def mostrar(db: Session = Depends(get_db)):
    # Obtener todas las reservaciones
    allReservas = db.query(ClassReservation).all()

    # Lista para almacenar las respuestas
    reservas = []

    # Iterar sobre todas las reservaciones
    for reserva in allReservas:
        # Obtener la clase asociada a la reservación
        clase = db.query(Class).filter(Class.id == reserva.id_clase).first()
        
        # Obtener el usuario asociado a la reservación
        user = db.query(User).filter(User.id == reserva.id_user).first()
        
        # Agregar la información de la reservación a la lista de reservas
        reservas.append({
            "id": reserva.id,
            "clase": clase.titulo if clase else None,  # Asegurarse de que clase exista
            "usuario": user.email if user else None,    # Asegurarse de que user exista
            "fecha": reserva.fecha_class,
            "monto": clase.precio,
            "estado": reserva.estado
        })
    
    return reservas

#Buscador de Reservacion
@app.get("/SearchClass/{email}/{state}")
async def buscarReservacion(email: str, state:OrderStatus, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == email).first()
    if not existing_user:
        raise HTTPException(status_code=400, detail="El usuario no existe")

    # Join entre reservaciones y clases para traer la información completa
    reservas = db.query(ClassReservation, Class).join(Class, Class.id == ClassReservation.id_clase)\
        .filter(ClassReservation.id_user == existing_user.id).all()

    if not reservas:
        raise HTTPException(status_code=400, detail="El usuario no tiene reservaciones")
    
    estado=db.query(ClassReservation).filter(ClassReservation.estado==state).all()
    
    if not estado:
        raise HTTPException(status_code=400, detail="El estado es incorrecto o el usuario no tiene reservaciones con ese estado")

    reservas_detalladas = [
        {
            "id": reserva.id,
            "clase": clase.titulo,
            "usuario":existing_user.nombre,
            "fecha": reserva.fecha_class,
            "monto": clase.precio,
            "estado": reserva.estado
        }
        for reserva, clase in reservas
    ]
    return reservas_detalladas


#Reservaciones de usuario
@app.get('/reservaciones/{user}')
async def mostrar_reservas(user: str, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user).first()
    if not existing_user:
        raise HTTPException(status_code=400, detail="El usuario no existe")

    # Join entre reservaciones y clases para traer la información completa
    reservas = db.query(ClassReservation, Class).join(Class, Class.id == ClassReservation.id_clase)\
        .filter(ClassReservation.id_user == existing_user.id).all()

    if not reservas:
        raise HTTPException(status_code=400, detail="El usuario no tiene reservaciones")

    reservas_detalladas = [
        {
            "id": reserva.id,
            "clase": clase.titulo,
            "usuario":existing_user.nombre,
            "fecha": reserva.fecha_class,
            "monto": clase.precio,
            "estado": reserva.estado
        }
        for reserva, clase in reservas
    ]
    return reservas_detalladas


# Reservar clase
@app.post("/reservarClass/")
async def reservar_class(reservation: ReservationClass, db: Session = Depends(get_db)):
    existing_class=db.query(Class).filter(Class.titulo == reservation.titulo_clase).first()
    if not existing_class:
        raise HTTPException(status_code=400,detail="la clase no existe")
    
    existing_user=db.query(User).filter(User.email == reservation.email_user).first()
    if not existing_user:
        raise HTTPException(status_code=400,detail="el usuario no existe")
    
    existing = db.query(ClassReservation).filter(
        ClassReservation.id_user == existing_user.id,
        ClassReservation.id_clase == existing_class.id,
        ClassReservation.fecha_class == reservation.date_class
    ).first()

    if existing:
        raise HTTPException(status_code=400, detail="Ya existe una reservación para esta clase en esta fecha")

    
    new_reservation = ClassReservation(
        id_clase=existing_class.id,
        id_user=existing_user.id,
        fecha_class=reservation.date_class,
    )
    db.add(new_reservation)
    db.commit()
    db.refresh(new_reservation)

    return new_reservation

#Editar el estado de la reserva
@app.put('/EditReserver/{id}/{state}')
async def editarReserva(id:int,state:OrderStatus,db: Session = Depends(get_db)):
    existing_reserv = db.query(ClassReservation).filter(ClassReservation.id == id).first()

    if not existing_reserv:
        raise HTTPException(status_code=404, detail="Reservacion no encontrada")

    existing_reserv.estado = state
    db.commit()
    db.refresh(existing_reserv)

    

@app.delete('/DeleteReservation/{id}')
async def eliminarReserva(id:int, db:Session=Depends(get_db)):
    existing_reserv = db.query(ClassReservation).filter(ClassReservation.id == id).first()
    if not existing_reserv:
        raise HTTPException(status_code=404, detail="Reservacion no encontrada")

    db.delete(existing_reserv)
    db.commit()
    
    return {"message": "reservacion eliminada"}



# Pagar clase
@app.post("/pagarClass/", response_model=None)
async def pagar_class(payment: PayClass, db: Session = Depends(get_db)):
    print("Datos recibidos:", payment.dict())

    try:
        existing_reservation = db.query(ClassReservation).filter(ClassReservation.id == payment.reservation_id).first()
        
        if not existing_reservation:
            raise HTTPException(status_code=400, detail="La reserva no existe")

        # Crear el nuevo pago relacionado con la reserva
        new_payment = Payment(
            reservation_id = existing_reservation.id,
            metodo_pago = payment.metodo_pago,
            monto = payment.monto,
            fecha_pago = payment.fecha_pago
        )
        
        db.add(new_payment)
        db.commit()
        db.refresh(new_payment)
        
        return new_payment
    except Exception as e:
        print("Error:", e)
        raise HTTPException(status_code=422, detail=str(e))


#GESTION MURAL====================================================================

@app.post('/mural/', response_model=None)
async def agregarmural(
    email: str = Form(...),
    titulo: str = Form(...),
    descripcion: str = Form(...), 
    foto: UploadFile = File(...),
    db: Session = Depends(get_db)):
    
    dat = db.query(User).filter(User.email == email).first()
    
    if not dat:
        raise HTTPException(status_code=400, detail="Inicie sesión antes")
    
    # Validar el tipo de archivo
    if foto.content_type not in ["image/jpeg", "image/png"]:
        raise HTTPException(status_code=400, detail="Formato de archivo no soportado")

    result = cloudinary.uploader.upload(await foto.read(), folder="productos")


    imagen_url = result["secure_url"]


    
    nuevo = Publication(
        id_user=dat.id,
        titulo=titulo,
        descripcion=descripcion,
        foto=imagen_url
    )
    
    db.add(nuevo)
    db.commit()
    db.refresh(nuevo)
    
    return {
        "id": nuevo.id,
        "id_user": nuevo.id_user,
        "titulo": nuevo.titulo,
        "descripcion": nuevo.descripcion,
        "foto": imagen_url
    }






@app.put("/editmural/{id}")
async def editmural(
    id: int,
    titulo: str = Form(...),
    descripcion: str = Form(...),
    foto: UploadFile = File(None),  # La imagen es opcional
    db: Session = Depends(get_db)
):
    # Buscar la publicación en la base de datos
    mural = db.query(Publication).filter(Publication.id == id).first()

    if mural is None:
        raise HTTPException(status_code=404, detail="Mural no encontrado")

    # Actualizar título y descripción
    mural.titulo = titulo
    mural.descripcion = descripcion

    # Si se proporciona una nueva imagen, subirla a Cloudinary
    if foto:
        if foto.content_type not in ["image/jpeg", "image/png"]:
            raise HTTPException(status_code=400, detail="Formato de archivo no soportado")

        result = cloudinary.uploader.upload(await foto.read(), folder="productos")
        imagen_url = result["secure_url"]
        mural.foto = imagen_url

    # Guardar los cambios en la base de datos
    db.commit()
    db.refresh(mural)

    # Respuesta con la información actualizada del mural
    return {
        "id": mural.id,
        "id_user": mural.id_user,
        "titulo": mural.titulo,
        "descripcion": mural.descripcion,
        "foto": mural.foto
    }


@app.delete("/deletemural/{id}")
async def deletemural(id: str, db: Session = Depends(get_db)):
    code = db.query(Publication).filter(Publication.id == id).first()

    if code is None:
        raise HTTPException(status_code=404, detail="publicacion no encontrada")

    db.delete(code)
    db.commit()

    return {"detail": "publicacion eliminada exitosamente"}

@app.get("/publicaciones/", response_model=list[mural])
async def publicaciones(db: Session = Depends(get_db)):
    allpublications = db.query(Publication).all()
    return [
        {
            "id": publication.id,
            "id_user": publication.id_user,
            "email": db.query(User).filter(User.id == publication.id_user).first().email,
            "titulo": publication.titulo,  # Cambiado a 'titulo'
            "descripcion": publication.descripcion,  # Cambiado a 'descripcion'
            "foto": f"http://localhost:8000{publication.foto}"  # Cambiado a 'foto'
        }
        for publication in allpublications
    ]



@app.get("/publicacionestitulo/{busca}")
async def buscarpublic(busca: str, db: Session = Depends(get_db)):
    allpublications = db.query(Publication).filter(Publication.titulo==busca).all()

    if not allpublications:
        raise HTTPException(status_code=404, detail="No se encontraron publicaciones con ese título")

    return [
        {
            "id": publication.id,
            "id_user": publication.id_user,
            "email": db.query(User).filter(User.id == publication.id_user).first().email,
            "titulo": publication.titulo,
            "descripcion": publication.descripcion,
            "foto": f"http://localhost:8000{publication.foto}"
        }
        for publication in allpublications
    ]

@app.get("/publicacionesusuario/{busca}")
async def buscarpublic(busca: str, db: Session = Depends(get_db)):
    # Buscar el usuario por su correo
    user = db.query(User).filter(User.email == busca).first()

    # Si no se encuentra el usuario, lanzar una excepción 404
    if not user:
        raise HTTPException(status_code=404, detail="No se encontró el usuario")

    # Obtener todas las publicaciones del usuario
    allpublications = db.query(Publication).filter(Publication.id_user == user.id).all()

    # Si el usuario no tiene publicaciones, lanzar una excepción 404
    if not allpublications:
        raise HTTPException(status_code=404, detail="No se encontraron publicaciones para este usuario")

    # Retornar los datos en formato JSON
    return [
        {
            "id": publication.id,
            "id_user": publication.id_user,
            "email": user.email,
            "titulo": publication.titulo,
            "descripcion": publication.descripcion,
            "foto": f"http://localhost:8000{publication.foto}"
        }
        for publication in allpublications
    ]

@app.get("/publicaciones/", response_model=list[mural])
async def publicaciones(db: Session = Depends(get_db)):
    allpublications = db.query(Publication).all()
    return [
        {
            "id": publication.id,
            "id_user": publication.id_user,
            "email": db.query(User).filter(User.id == publication.id_user).first().email,
            "titulo": publication.titulo,  # Cambiado a 'titulo'
            "descripcion": publication.descripcion,  # Cambiado a 'descripcion'
            "foto": f"http://localhost:8000{publication.foto}"  # Cambiado a 'foto'
        }
        for publication in allpublications
    ]
