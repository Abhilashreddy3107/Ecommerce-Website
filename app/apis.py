from app import application
from flask import jsonify, Response, session
from app.models import *
from app import *
import uuid
import datetime
from marshmallow import Schema, fields
from flask_restful import Resource, Api
from flask_apispec.views import MethodResource
from flask_apispec import marshal_with, doc, use_kwargs
import json

ERROR_ADMIN_MESSAGE = "Only Admin can call this Endpoint"

class SignUpRequest(Schema):
    username = fields.Str(default = "username")
    password = fields.Str(default = "password")
    name = fields.Str(default = "name")
    level = fields.Int(default = 0)

class APIResponse(Schema):
    message = fields.Str(default="Success")

class LoginRequest(Schema):
    username = fields.Str(default="username")
    password = fields.Str(default="password")

class AddVendorRequest(Schema) :
    user_id = fields.Str(default="user_id")

class AddItemRequest(Schema):
    item_name = fields.Str(default="item name")
    calories_per_gm = fields.Int(default=100)
    available_quantity = fields.Int(default=100)
    restaurant_name = fields.Str(default="ahc hotel")
    unit_price = fields.Int(default = 0)

class VendorsListResponse(Schema):
    vendors = fields. List(fields.Dict())

class ItemListResponse(Schema):
    items = fields.List(fields.Dict())

class APIResponse(Schema):
    message = fields.Str(default="Success")

class ItemsOrderList(Schema):
    items = fields. List(fields.Dict())

class PlaceOrderRequest(Schema):
    order_id = fields.Str(default="order_id")

class ListOrderResponse(Schema) :
    orders = fields.List(fields.Dict())    

# SignUpAPI

class SignUpAPI(MethodResource, Resource):
    @doc(description='SignUp API', tags=['SignUp API'])
    @use_kwargs(SignUpRequest, location=('json'))
    @marshal_with(APIResponse)
    def post(self, **kwargs):
        try:
            user = User(
                uuid.uuid4(),
                kwargs['name'],
                kwargs['username'],
                kwargs['password'],
                kwargs['level']
            )
            db.session.add(user)
            db.session.commit()
            return APIResponse().dump(dict(message='User is successfully registered')), 201
        except Exception as e:
            print(str(e))  # Log the error instead of just printing
            return APIResponse().dump({'message': f'Not able to register User: {str(e)}'}), 500  # Use a more appropriate status code

# Assuming you have an instance of Flask called 'app'
api.add_resource(SignUpAPI, '/signup')
docs.register(SignUpAPI)

#LoginAPI

class LoginAPI(MethodResource, Resource):
    @doc(description='Login API', tags=['Login API'])
    @use_kwargs(LoginRequest, location=('json'))
    @marshal_with(APIResponse)  # marshalling
    def post(self, **kwargs):
        try:
            user = User.query.filter_by(username=kwargs['username'], password=kwargs['password']).first()
            if user:
                print('logged in')
                session['user_id'] = user.user_id
                print(f'User id: {str(session["user_id"])}')
                return APIResponse().dump(dict(message='User is successfully logged in')), 200
            else:
                return APIResponse().dump(dict(message='User not found')), 404
        except Exception as e:
            print(str(e))
            return APIResponse().dump(dict(message=f'Not able to login User: {str(e)}')), 400

api.add_resource(LoginAPI, '/login')
docs.register(LoginAPI)

# #LogoutAPI

class LogoutAPI(MethodResource, Resource):
    @doc(description='Logout API', tags=['Logout API'])
    @marshal_with(APIResponse)  # marshalling
    def post(self, **kwargs):
        try:
            if session.get('user_id'):
                session['user_id'] = None
                return APIResponse().dump(dict(message='User is successfully logged out')), 200
            else:
                return APIResponse().dump(dict(message='User is not logged in')), 401
        except Exception as e:
            return APIResponse().dump(dict(message=f'Not able to logout User: {str(e)}')), 400

api.add_resource(LogoutAPI, '/logout')
docs.register(LogoutAPI)

#AddVendorAPI
 
class AddVendorAPI(MethodResource, Resource):
    @doc(description='Add Vendor API', tags=['Vendor API'])
    @use_kwargs(AddVendorRequest, location=('json'))
    @marshal_with(APIResponse)  # marshalling
    def post(self, **kwargs):
        try:
            if session.get('user_id'):
                user_id = session['user_id']
                user_type = User.query.filter_by(user_id=user_id).first().level

                if user_type == 2:
                    vendor_user_id = kwargs['user_id']
                    user = User.query.filter_by(user_id=vendor_user_id).first()

                    # Check if the user exists and has the required permission to become a vendor (Level 0 for customers)
                    if user and user.level == 0:
                        # Make the user a vendor by updating the level to 1
                        user.level = 1
                        db.session.commit()
                        return APIResponse().dump(dict(message='Vendor is successfully added')), 200
                    else:
                        return APIResponse().dump(dict(message='User not found or does not have permission to become a vendor')), 404
                else:
                    return APIResponse().dump(dict(message=ERROR_ADMIN_MESSAGE)), 405
            else:
                return APIResponse().dump(dict(message='User is not logged in')), 401
        except Exception as e:
            print(str(e))
            return APIResponse().dump(dict(message=f'Not able to add vendor: {str(e)}')), 400

api.add_resource(AddVendorAPI, '/add_vendor')
docs.register(AddVendorAPI)


#GetVendorsAPI
class GetVendorsAPI(MethodResource, Resource):
    @doc(description='Get All Vendors API', tags=['Vendor API'])
    @marshal_with(VendorsListResponse)  # marshalling
    def get(self):
        try:
            if session.get('user_id'):
                user_id = session['user_id']
                user_type = User.query.filter_by(user_id=user_id).first().level

                if user_type == 1:  # Assuming level 1 corresponds to vendors
                    vendors = User.query.filter_by(level=1)
                    vendors_list = []

                    for vendor in vendors:
                        items = Item.query.filter_by(vendor_id=vendor.user_id, is_active=1)
                        vendor_dict = {'vendor_id': vendor.user_id, 'name': vendor.name, 'items': []}

                        vendors_list.append(vendor_dict)

                    return VendorsListResponse().dump(dict(vendors=vendors_list)), 200
                else:
                    return APIResponse().dump(dict(message='User does not have permission to access vendors')), 403
            else:
                return APIResponse().dump(dict(message='User is not logged in')), 401

        except Exception as e:
            print(str(e))
            return APIResponse().dump(dict(message=f'Error retrieving vendors: {str(e)}')), 500

api.add_resource(GetVendorsAPI, '/get_vendors')
docs.register(GetVendorsAPI)

#AdditemAPI

class AddItemAPI(MethodResource, Resource):
    @doc(description='Add Item API', tags=['Items API'])
    @use_kwargs(AddItemRequest, location=('json'))
    @marshal_with(APIResponse)  # marshalling
    def post(self, **kwargs):
        try:
            if session.get('user_id'):
                user_id = session['user_id']
                user_type = User.query.filter_by(user_id=user_id).first().level

                if user_type == 1:  # Assuming level 1 corresponds to vendors
                    item = Item(
                        uuid.uuid4(),
                        session['user_id'],
                        kwargs['item_name'],
                        kwargs['calories_per_gm'],
                        kwargs['available_quantity'],
                        kwargs['restaurant_name'],
                        kwargs['unit_price']
                    )

                    db.session.add(item)
                    db.session.commit()

                    return APIResponse().dump(dict(message='Item is successfully added')), 200
                else:
                    return APIResponse().dump(dict(message='LoggedIn User is not a Vendor')), 405
            else:
                return APIResponse().dump(dict(message='Vendor is not logged in')), 401

        except Exception as e:
            print(str(e))
            return APIResponse().dump(dict(message=f'Not able to add item: {str(e)}')), 400

api.add_resource(AddItemAPI, '/add_item')
docs.register(AddItemAPI)

#ListItemsAPI

class ListItemsAPI(MethodResource, Resource):
    @doc(description='List All Items API', tags=['Items API'])
    @marshal_with(ItemListResponse)  # marshalling
    def get(self):
        try:
            if session.get('user_id'):
                items = Item.query.all()
                items_list = list()

                for item in items:
                    item_dict = dict(
                        item_id=item.item_id,
                        item_name=item.item_name,
                        calories_per_gm=item.calories_per_gm,
                        available_quantity=item.available_quantity,
                        unit_price=item.unit_price
                    )
                    items_list.append(item_dict)

                return ItemListResponse().dump(dict(items=items_list)), 200
            else:
                return APIResponse().dump(dict(message='User is not logged in')), 401

        except Exception as e:
            print(str(e))
            return APIResponse().dump(dict(message=f'Not able to list items: {str(e)}')), 400

api.add_resource(ListItemsAPI, '/list_items')
docs.register(ListItemsAPI)

#CreateItemOrderAPI
class CreateItemOrderAPI(MethodResource, Resource):
    @doc(description='Create Items Order API', tags=['Order API'])
    @use_kwargs(ItemsOrderList, location=('json'))
    @marshal_with(APIResponse)  # marshalling
    def post(self, **kwargs):
        try:
            if session.get('user_id'):
                user_id = session['user_id']
                user_type = User.query.filter_by(user_id=user_id).first().level
                print(user_id)

                if user_type == 0:
                    order_id = uuid.uuid4()
                    order = Order(order_id, user_id)
                    db.session.add(order)

                    for item in kwargs['items']:
                        item = dict(item)
                        order_item = OrderItems(
                            uuid.uuid4(),
                            order_id,
                            item['item_id'],
                            item['quantity']
                        )
                        db.session.add(order_item)

                    db.session.commit()
                    return APIResponse().dump(dict(message='Items for the Order are successfully added')), 200
                else:
                    return APIResponse().dump(dict(message='LoggedIn User is not a Customer')), 405
            else:
                return APIResponse().dump(dict(message='Customer is not logged in')), 401

        except Exception as e:
            print(str(e))
            return APIResponse().dump(dict(message=f'Not able to add items for ordering: {str(e)}')), 400

api.add_resource(CreateItemOrderAPI, '/create_items_order')
docs.register(CreateItemOrderAPI)

#PlaceOrderAPI
class PlaceOrderAPI(MethodResource, Resource):
    @doc(description='Place Order API', tags=['Order API'])
    @use_kwargs(PlaceOrderRequest, location=('json'))
    @marshal_with(APIResponse)  # marshalling
    def post(self, **kwargs):
        try:
            if session.get('user_id'):
                user_id = session['user_id']
                user_type = User.query.filter_by(user_id=user_id).first().level
                print(user_id)

                if user_type == 0:
                    order_items = OrderItems.query.filter_by(order_id=kwargs['order_id'], is_active=1)
                    order = Order.query.filter_by(order_id=kwargs['order_id'], is_active=1).first()
                    total_amount = 0

                    for order_item in order_items:
                        item_id = order_item.item_id
                        quantity = order_item.quantity

                        item = Item.query.filter_by(item_id=item_id, is_active=1).first()

                        total_amount += quantity * item.unit_price

                        item.available_quantity = item.available_quantity - quantity

                    order.total_amount = total_amount
                    db.session.commit()
                    return APIResponse().dump(dict(message='Order is successfully placed.')), 200
                else:
                    return APIResponse().dump(dict(message='LoggedIn User is not a Customer')), 405
            else:
                return APIResponse().dump(dict(message='Customer is not logged in')), 401

        except Exception as e:
            print(str(e))
            return APIResponse().dump(dict(message=f'Not able to place order: {str(e)}')), 400

api.add_resource(PlaceOrderAPI, '/place_order')
docs.register(PlaceOrderAPI)

#ListOrdersByCustomerAPI
class ListOrdersByCustomerAPI(MethodResource, Resource):
    @doc(description='List Orders by Customer API', tags=['Order API'])
    # @marshal_with(ListOrderResponse) # marshalling
    def get(self, **kwargs):
        try:
            if session.get('user_id'):
                user_id = session['user_id']
                user_type = User.query.filter_by(user_id=user_id).first().level
                print(user_id)

                if user_type == 0:
                    orders = Order.query.filter_by(user_id=user_id, is_active=1)
                    order_list = list()

                    for order in orders:
                        order_items = OrderItems.query.filter_by(order_id=order.order_id, is_active=1)

                        order_dict = dict()
                        order_dict['order_id'] = order.order_id
                        order_dict['items'] = list()

                        for order_item in order_items:
                            order_item_dict = dict()
                            order_item_dict['item_id'] = order_item.item_id
                            order_item_dict['quantity'] = order_item.quantity
                            order_dict['items'].append(order_item_dict)

                        order_list.append(order_dict)

                    return ListOrderResponse().dump(dict(orders=order_list)), 200
                else:
                    return APIResponse().dump(dict(message='LoggedIn User is not a Customer')), 405
            else:
                return APIResponse().dump(dict(message='Customer is not logged in')), 401

        except Exception as e:
            print(str(e))
            return APIResponse().dump(dict(message=f'Not able to list orders: {str(e)}')), 400

api.add_resource(ListOrdersByCustomerAPI, '/list_orders')
docs.register(ListOrdersByCustomerAPI)

#ListAllOrdersAPI

class ListAllOrdersAPI(MethodResource, Resource):
    @doc(description='List All Orders API', tags=['Order API'])
    # @marshal_with(ListOrderResponse) # marshalling
    def get(self, **kwargs):
        try:
            if session.get('user_id'):
                user_id = session['user_id']
                user_type = User.query.filter_by(user_id=user_id).first().level
                print(user_id)

                if user_type == 2:
                    orders = Order.query.filter_by(is_active=1)
                    order_list = list()

                    for order in orders:
                        order_items = OrderItems.query.filter_by(order_id=order.order_id, is_active=1)

                        order_dict = dict()
                        order_dict['order_id'] = order.order_id
                        order_dict['items'] = list()

                        for order_item in order_items:
                            order_item_dict = dict()
                            order_item_dict['item_id'] = order_item.item_id
                            order_item_dict['quantity'] = order_item.quantity
                            order_dict['items'].append(order_item_dict)

                        order_list.append(order_dict)

                    return ListOrderResponse().dump(dict(orders=order_list)), 200
                else:
                    return APIResponse().dump(dict(message='LoggedIn User is not an Admin')), 405
            else:
                return APIResponse().dump(dict(message='Admin is not logged in')), 401

        except Exception as e:
            print(str(e))
            return APIResponse().dump(dict(message=f'Not able to list all orders: {str(e)}')), 400

api.add_resource(ListAllOrdersAPI, '/list_all_orders')
docs.register(ListAllOrdersAPI)
