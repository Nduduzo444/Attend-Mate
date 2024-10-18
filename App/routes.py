from flask import flash, redirect,url_for, render_template,request, session
from App import app, db, bcrypt
from App.models import User, Admin, Child, Notification, Alert
from datetime import datetime


# Main INDEX
@app.route('/')
def index():
    return render_template('index.html', title="")

@app.route('/contact')
def getContact():
    return render_template('contact.html', title="")

@app.route('/about')
def about():
    return render_template('about.html', title="About Us")


# ___________________________Admin Area__________________________________________________________________________

#Admin login
@app.route('/admin/', methods=['POST', 'GET'])
def admin_index():
    error_message = None
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            error_message = 'Please enter both username and password.'
        else:
            admin = Admin.query.filter_by(username=username).first()
            if admin and bcrypt.check_password_hash(admin.password, password):
                session['admin_id'] = admin.id
                session['admin_username'] = admin.username
                return redirect('/admin/dashboard')
            else:
                error_message = 'Invalid username or password.'
                
    return render_template('admin/index.html', title="Admin Login", error_message=error_message)


# Admin Dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_username' not in session:
        return redirect('/admin/')
    
    totalUsers = User.query.count()
    totalApproved = User.query.filter_by(status=1).count()
    pendingUsers = User.query.filter_by(status=0).count()
    
    return render_template('admin/dashboard.html', title="Admin Dashboard", 
                           totalUsers=totalUsers, totalApproved=totalApproved, pendingUsers=pendingUsers)

# Admin get all User
@app.route('/admin/all-users', methods=['GET', 'POST'])
def admin_get_all_users():
    search = request.form.get('search')  # Getting search input from form
    
    if search:  # Check if search is not None or an empty string
        users = User.query.filter(User.fname.like(f"%{search}%")).all()
    else:
        users = User.query.all()  # If no search, return all users
    
    return render_template('admin/all-users.html', users=users)


@app.route('/admin/approve-user/<int:id>')
def admin_approve(id):
    if 'admin_username' not in session:
        return redirect('/admin/')
    
    User.query.filter_by(id=id).update(dict(status=1))
    db.session.commit()
   
    return redirect('/admin/all-users')

@app.route('/admin/set-authority/<int:id>')
def set_authority(id):
    if 'admin_username' not in session:
        return redirect('/admin/')
    
    User.query.filter_by(id=id).update(dict(isAuthority=1))
    db.session.commit()
    flash('User set as School Authority', 'success')
    return redirect(f'/admin/assign-grade/{id}')

@app.route('/admin/remove-authority/<int:id>', methods=['POST'])
def remove_authority(id):
    if 'admin_username' not in session:
        return redirect('/admin/')

    # Update the user's authority status in the database
    User.query.filter_by(id=id).update(dict(isAuthority=0))
    db.session.commit()
    
    return redirect('/admin/all-users')  # Redirect to the admin page


@app.route('/admin/assign-grade/<int:id>', methods=['GET', 'POST'])
def assign_grade(id):
    if 'admin_username' not in session:
        return redirect('/admin/')
    
    user = User.query.get(id)
    if user is None or user.isAuthority == 0:
        return redirect('/admin/all-users')
    
    if request.method == 'POST':
        grade = request.form.get('grade')
        # You can add validation to check if grade is valid (0-7)
        try:
            grade = int(grade)
            if grade < 0 or grade > 7:
                raise ValueError("Invalid grade")
        except ValueError:
            flash('Please select a valid grade.', 'danger')
            return redirect(f'/admin/assign-grade/{user.id}')
        
        # Save the grade to the database (this could be in a separate Authority model if needed)
        user.managed_grade = grade  # Assuming you're storing the grade in the User model
        db.session.commit()
        
        return redirect('/admin/all-users')
    
    return render_template('admin/assign-grade.html', user=user)

# Change admin password
@app.route('/admin/change-admin-password', methods=['POST', 'GET'])
def admin_change_password():
    if 'admin_username' not in session:
        return redirect('/admin/')
    
    admin = Admin.query.get(1)
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            
            return redirect('/admin/change-admin-password')
        
        Admin.query.filter_by(username=username).update(dict(password=bcrypt.generate_password_hash(password, 10)))
        db.session.commit()
        flash('Password changed successfully', 'success')
        return redirect('/admin/dashboard')
    
    return render_template('admin/admin-change-password.html', title="Admin Change Password", admin=admin)

@app.route('/admin/logout')
def admin_logout():
    session.clear()
  
    
    return redirect('/')



@app.route('/admin/delete-user/<int:user_id>', methods=["POST"])
def delete_user(user_id):
    user = User.query.get(user_id)
    
    if user is None:
        
        return redirect('/admin/all-users')

    # Check for associated children
    children = Child.query.filter_by(parent_id=user.id).all()  # Assuming `Child` is your child model
    
    # Delete associated children first
    for child in children:
        db.session.delete(child)
    
    # Now delete the parent user
    db.session.delete(user)
    db.session.commit()

    flash('User and associated children deleted successfully.', 'success')
    return redirect('/admin/all-users')






# ___________________________User Area_______________________________

# User Login
@app.route('/user/', methods=["POST", "GET"])
def user_index():
    error_message = None  # Initialize variable for error message

    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        # Query the database for the user by email
        user = User.query.filter_by(email=email).first()

        if user:
            # Check if the provided password matches the hashed password
            if bcrypt.check_password_hash(user.password, password):
                if user.status == 0:
                    error_message = 'Your account is not approved yet'
                else:
                    # Successful login logic
                    session['user_id'] = user.id
                    session['fname'] = user.fname
                    session['isAuthority'] = user.isAuthority

                    # Redirect based on authority
                    return redirect('/school-authority/dashboard' if user.isAuthority == 1 else '/user/dashboard')
            else:
                error_message = 'Invalid password'  # Incorrect password
        else:
            error_message = 'User does not exist'  # User does not exist

        # Render template with error message
        return render_template('user/index.html', title="User Login", error_message=error_message)

    # Render login template for GET request
    return render_template('user/index.html', title="User Login")

# User Register
import re
@app.route('/user/signup', methods=['POST', 'GET'])
def user_sign_up():
    success_message = None  # Initialize variable for success message
    error_message = None    # Initialize variable for error message

    if request.method == 'POST':
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')

        # Validate that all fields are filled
        if not all([fname, lname, email, username, password]):
            error_message = 'Please fill in all the fields.'
            return render_template('user/signup.html', title="User Registration", error_message=error_message)

        # Check if names contain numbers or special characters
        if not re.match("^[A-Za-z]+$", fname) or not re.match("^[A-Za-z]+$", lname):
            error_message = 'Names should only contain letters and no special characters or numbers.'
            return render_template('user/signup.html', title="User Registration", error_message=error_message)

        # Check if the account already exists
        if User.query.filter_by(email=email).first():
            error_message = 'An account with this email already exists.'
            return render_template('user/signup.html', title="User Registration", error_message=error_message)

        # Hash the password and create the user
        hash_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(fname=fname, lname=lname, email=email, username=username, password=hash_password)
        db.session.add(user)
        db.session.commit()

        # Prepare success message
        success_message = 'Account created successfully. The Admin will approve your account shortly.'
        return render_template('user/signup.html', title="User Registration", success_message=success_message)

    return render_template('user/signup.html', title="User Registration")


# User Dashboard
@app.route('/user/dashboard')
def user_dashboard():
    if 'user_id' not in session:
        return redirect('/user/')

    user_id = session['user_id']
    unread_count = Notification.query.filter_by(parent_id=user_id, is_read=False).count()  # Adjust the model as needed

    
    return render_template('user/dashboard.html', title="User Dashboard", unread_count=unread_count)

@app.route('/user/profile-settings', methods=['GET', 'POST'])
def profile():
    user_id = session.get('user_id')

    if not user_id:
       
        return redirect(url_for('login'))

    user = User.query.get(user_id)

    if request.method == 'POST':
        # Retrieve updated profile form data
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        contact_number = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        user.fname = fname
        user.lname = lname
        user.username = contact_number
        user.email = email

        if password:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user.password = hashed_password

        try:
            db.session.commit()
            flash('Your profile was successfully updated!', 'success')
        except Exception as e:
            db.session.rollback()
            

        return redirect(url_for('profile'))

    return render_template('/user/profile-settings.html', user=user)


    # Pre-fill form with current user data
    return render_template('/user/profile-settings.html', user=user)

@app.route('/admin/user-list', methods=['GET'])
def user_list():
    # Fetch all users from the User table
    users = User.query.all()
    return render_template('admin/user_list.html', users=users)



@app.route('/user/add_child', methods=['GET', 'POST'])
def add_child():
    success_message = None
    error_message = None

    if request.method == 'POST':
        # Retrieve form data
        fullname = request.form['fullname']
        grade = request.form['grade']
        gender = request.form['gender']
        dob_str = request.form['dob']
        
        # Validate fullname
        if not re.match("^[a-zA-Z\s]+$", fullname):
            error_message = 'Error: Full name must only contain letters and spaces.'
            return render_template('user/add_child.html', error_message=error_message)

        # Convert string to date object
        try:
            dob = datetime.strptime(dob_str, '%Y-%m-%d').date()
        except ValueError:
            error_message = 'Error: Invalid date format. Please use YYYY-MM-DD.'
            return render_template('user/add_child.html', error_message=error_message)

        # Retrieve user ID from session
        user_id = session.get('user_id')
        
        if user_id is None:
            error_message = 'Error: User is not logged in.'
            return render_template('user/add_child.html', error_message=error_message)

        # Create a new Child object
        new_child = Child(
            full_name=fullname,
            grade=grade,
            gender=gender,
            dob=dob,
            parent_id=user_id
        )

        try:
            db.session.add(new_child)
            db.session.commit()
            success_message = 'Child added successfully!'
            return render_template('user/add_child.html', success_message=success_message)

        except Exception as e:
            db.session.rollback()
            error_message = f'Error: Could not add child. Please try again. {str(e)}'
            return render_template('user/add_child.html', error_message=error_message)

    return render_template('user/add_child.html')

@app.route('/user/notification', methods=['GET'])
def view_notifications():
    '''if 'username' not in session:
        return redirect('/login/')'''

    user_id = session['user_id']
    parent = User.query.get(user_id)

    # Retrieve notifications for the parent
    notifications = Notification.query.filter_by(parent_id=parent.id).order_by(Notification.timestamp.desc()).all()

    # Mark notifications as read
    for notification in notifications:
        notification.is_read = True
    db.session.commit()

    return render_template('user/notification.html', notifications=notifications)

@app.route('/user/manage-child', methods=['GET', 'POST'])
def manage_child():
    success_message = None
    error_message = None

    # Retrieve the user's children from the database (assuming you have a way to get them)
    user_id = session.get('user_id')
    children = Child.query.filter_by(parent_id=user_id).all()  # Example query to get user's children

    if request.method == 'POST':
        child_id = request.form['child_id']
        fullname = request.form['fullname']
        grade = request.form['grade']
        gender = request.form['gender']
        dob_str = request.form['dob']

        # Validate fullname
        if not re.match("^[a-zA-Z\s]+$", fullname):
            error_message = 'Error: Full name must only contain letters and spaces.'
            return render_template('user/manage-child.html', children=children, error_message=error_message)

        # Convert string to date object
        try:
            dob = datetime.strptime(dob_str, '%Y-%m-%d').date()
        except ValueError:
            error_message = 'Error: Invalid date format. Please use YYYY-MM-DD.'
            return render_template('user/manage-child.html', children=children, error_message=error_message)

        # Update the child's information in the database
        try:
            child = Child.query.get(child_id)
            if child:
                child.full_name = fullname
                child.grade = grade
                child.gender = gender
                child.dob = dob
                db.session.commit()
                success_message = 'Child information updated successfully!'
            else:
                error_message = 'Error: Child not found.'
        except Exception as e:
            db.session.rollback()
            error_message = f'Error: Could not update child. {str(e)}'

    return render_template('user/manage-child.html', children=children, success_message=success_message, error_message=error_message)




# Route for parent to notify about child's status
@app.route('/user/notify-school', methods=['GET', 'POST'])
def notify_school():
    if 'user_id' not in session:
        return redirect('/user/')

    user_id = session['user_id']
    parent = User.query.get(user_id)
    children = parent.children  # Get all the children associated with the parent

    if request.method == 'POST':
        child_id = request.form.get('child_id')
        status = request.form.get('status')

        # Retrieve child
        child = Child.query.get(child_id)
        if not child:
            
            return redirect('/user/notify-school')

        # Retrieve authority managing the child's grade
        school_authority = User.query.filter_by(isAuthority=1, managed_grade=child.grade).first()

        if not school_authority:
            return redirect('/user/notify-school')

        # Create the alert message based on status
        if status == 'arrived':
            alert_message = f"{child.full_name} has arrived home at {datetime.now().strftime('%H:%M')}."
        elif status == 'departed':
            alert_message = f"{child.full_name} has departed from home at {datetime.now().strftime('%H:%M')}."
        elif status == 'absent':
            alert_message = f"{child.full_name} is absent today."
        else:
            
            return redirect('/user/notify-school')

        # Create and store the alert for the school authority
        alert = Alert(
            child_id=child.id,
            status=status, 
            authority_id=school_authority.id,  # Set the correct authority
            timestamp=datetime.now()
        )
        db.session.add(alert)

        try:
            db.session.commit()
            flash('Alert sent to the school.', 'success')
        except Exception as e:
            db.session.rollback()  # Roll back if there's an error
            
        return redirect('/user/dashboard')

    return render_template('user/notify-school.html', children=children)







#User Logout
@app.route('/user/logout')
def user_logout():
    session.clear()
    
    
    return redirect('/')

# Change User Password
@app.route('/user/change-password', methods=["POST", "GET"])
def user_change_password():
    
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash('Please fill in the fields', 'danger')
            return redirect('/user/change-password')

        user = User.query.filter_by(email=email).first()
        if user:
            hashed_password = bcrypt.generate_password_hash(password, 10)
            user.password = hashed_password
            db.session.commit()
            
            return redirect('/user/dashboard')
       
    
    return render_template('user/change-password.html', title="Change Password")

# ________________________School Authority Area__________________________________

@app.route('/school-authority/dashboard')
def school_authority_dashboard():
    if not session.get('isAuthority'):
        return redirect('/user/')
    
    return render_template('school-authority/dashboard.html', title="School Authority Dashboard")
#################################################################################################################################

@app.route('/school-authority/manage-attendance', methods=['GET', 'POST'])
def manage_attendance():
    user_id = session['user_id']
    user = User.query.get(user_id)

    if user.isAuthority != 1:
        flash('You do not have permission to manage attendance.', 'danger')
        return redirect('/')

    children = Child.query.filter_by(grade=user.managed_grade).all()

    if request.method == 'POST':
        child_id = request.form.get('child_id')
        action = request.form.get('action')

        child = Child.query.get(child_id)

        if action == 'present':
            # Capture current time for time in
            child.time_in = datetime.now()
            child.time_out = None  # Reset time out if marked present
            db.session.commit()
            
            notify_parent(child, 'present')

        elif action == 'absent':
            # Set both time_in and time_out to None
            child.time_in = None
            child.time_out = None
            db.session.commit()
            
            notify_parent(child, 'absent')

        elif action == 'time_out':
            # Capture current time for time out
            if child.time_in:  # Ensure time in has been marked
                child.time_out = datetime.now()
                db.session.commit()
                
                notify_parent(child, 'time_out')  # Notify the parent about time out

        # Redirect back to the same page
        return redirect(url_for('manage_attendance'))

    return render_template('school-authority/manage-attendance.html', title="Manage Attendance", user=user, children=children)

def notify_parent(child, status):
    parent = User.query.get(child.parent_id)  # Get the parent using the foreign key
    if parent:
        # Create the notification message based on the status
        if status == 'present':
            message = f"{child.full_name} is marked present at {child.time_in.strftime('%H:%M')}."
        elif status == 'absent':
            message = f"{child.full_name} is marked absent."
        elif status == 'time_out':
            message = f"{child.full_name} has left the school at {child.time_out.strftime('%H:%M')}."

        # Store the notification
        notification = Notification(parent_id=parent.id, message=message)
        db.session.add(notification)
        db.session.commit()



        
        
@app.route('/school-authority/alert', methods=['GET'])
def view_alerts():
    if 'user_id' not in session:
        return redirect('/login/')

    user_id = session['user_id']
    authority = User.query.get(user_id)

    # Ensure the user is a school authority
    if authority.isAuthority != 1:
       
        return redirect('/user/dashboard')

    # Retrieve alerts for the managed grade
    alerts = Alert.query.filter(Alert.child.has(grade=authority.managed_grade)).order_by(Alert.timestamp.desc()).all()

    if not alerts:
       
        return render_template('school-authority/alert.html', alerts=None)

    return render_template('school-authority/alert.html', alerts=alerts)










