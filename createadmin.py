from app import app, db, User

def create_admin_user(username, first_name, last_name, member_id, email, phone, city, state, aviary, password):
    with app.app_context():
        # Check if the username already exists
        if User.query.filter_by(username=username).first():
            print(f"User {username} already exists.")
            return
        
        # Create a new admin user
        admin_user = User(
            username=username,
            first_name=first_name,
            last_name=last_name,
            member_id=member_id,
            email=email,
            phone=phone,
            city=city,
            state=state,
            aviary=aviary
        )
        admin_user.set_password(password)
        
        # Add to the session and commit
        db.session.add(admin_user)
        db.session.commit()
        print(f"Admin user {username} created successfully.")

if __name__ == "__main__":
    # Example usage
    create_admin_user(
        username='ADM-delfinort', 
        first_name='Delfino', 
        last_name='Administrador', 
        member_id='a01', 
        email='delfinort@gmail.com', 
        phone='3333333333',
        city='Guadalajara', 
        state='Jalisco', 
        aviary='AdminAdmin', 
        password='deldeoxisldn'
    )