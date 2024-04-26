import csv
import uuid
from sqlalchemy.exc import IntegrityError
from app import app, db, User

def set_initial_password(first_name, last_name):
    """Generates an initial password, using a fallback if last_name is empty."""
    last_initial = last_name[0] if last_name else 'x'
    return first_name + last_initial

def get_initials(full_name):
    """Extract initials from the full name."""
    return ''.join([name[0] for name in full_name.split() if name])

def create_username(first_name, last_name):
    """
    Generates a unique username using the first word of the first name and the initials of the full name.
    """
    first_word_first_name = first_name.split()[0].lower()
    full_name_initials = get_initials(f"{first_name} {last_name}").lower()
    return f"{first_word_first_name}{full_name_initials}"

def ensure_unique_username(desired_username, existing_usernames):
    """Ensures that the generated username is unique, altering it if necessary."""
    username = desired_username
    append_index = 1
    
    while username in existing_usernames:
        # Adding a UUID as a fallback to ensure uniqueness if collision occurs.
        username = f"{desired_username}{uuid.uuid4().hex[:4]}"
        break
            
    existing_usernames.add(username)  # Track the newly generated unique username
    return username

def get_next_member_id():
    """Fetches the next member_id by incrementing the current maximum."""
    max_id_user = User.query.order_by(User.member_id.desc()).first()
    return str(int(max_id_user.member_id) + 1).zfill(3) if max_id_user else "001"

def create_users_from_csv(csv_file_path):
    ctx = app.app_context()
    ctx.push()
    
    existing_usernames = set(user.username for user in User.query.all())  # Load existing usernames

    with open(csv_file_path, newline='', encoding='utf-8') as csvfile:
        user_reader = csv.reader(csvfile, delimiter=';')
        next(user_reader, None)  # Skip header row
        
        for row in user_reader:
            if len(row) < 7:
                print("Skipping incomplete row:", row)
                continue
            # Row structure is expected as: Criador #, Nombre(s), Apellido(s), Estado, Ciudad, Telefono, Email, Aviario
            first_name, last_name_paterno, last_name_materno, state, city, phone, email, aviary = row[1:9]

            last_name = f"{last_name_paterno} {last_name_materno}".strip()

            initial_password = set_initial_password(first_name, last_name_paterno)
            
            desired_username = create_username(first_name, last_name)
            username = ensure_unique_username(desired_username, existing_usernames)
            
            member_id = get_next_member_id()  # Dynamically generate a unique member_id
            
            try:
                user = User(username=username, first_name=first_name, last_name=last_name,
                            member_id=member_id, email=email, phone=phone, city=city, 
                            state=state, aviary=aviary)
                user.set_password(initial_password)
                
                db.session.add(user)
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                print(f"Failed to add user with email: {email}. Username or Member ID may already exist.")

create_users_from_csv('users.csv')