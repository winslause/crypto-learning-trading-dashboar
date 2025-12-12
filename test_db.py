from app import Base, engine, SessionLocal, User

# Create tables
Base.metadata.create_all(bind=engine)

# Test database operations
db = SessionLocal()
try:
    # Try to create a user
    user = User(
        username="testuser",
        email="test@example.com",
        hashed_password="testpassword",
        first_name="Test",
        last_name="User",
        country="US",
        timezone="UTC-5",
        bio="",
        experience="intermediate",
        trading_type="futures",
        default_timeframe="1h",
        theme="dark",
        language="English",
        chart_type="candlestick",
        price_alerts=True,
        show_trading_stats=False,
        allow_messages=True,
        email_marketing=False,
        email_notifications=True,
        push_notifications=True,
        sms_notifications=False,
        enable_2fa=False
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    print(f"User created successfully: {user.username}")

    # Try to query the user
    queried_user = db.query(User).filter(User.username == "testuser").first()
    print(f"User queried successfully: {queried_user.username}")

except Exception as e:
    print(f"Error: {e}")
    db.rollback()
finally:
    db.close()