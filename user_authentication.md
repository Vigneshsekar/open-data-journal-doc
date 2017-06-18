###  Simple User authentication implemented in the open data journal application.

In this post, we will look at how a simple user authentication has been implemented in our web app as a beginning. We had our project skeleton ready using the ‘mix’ tool that is used to maintain Elixir projects.

Coming to the user authentication part, we used [Guardian](https://github.com/ueberauth/guardian) and [Comeonin](https://github.com/riverrun/comeonin) libraries to make the work easier.

To start, we first generate our User model to define our users with the following schema. We shall use the Phoenix generator for it. You can find more on phoenix-specific and ecto-specific mix tasks,[here](http://www.phoenixframework.org/docs/mix-tasks)

      schema "users" do
        field :first_name, :string
        field :last_name, :string
        field :email, :string
        field :password, :string, virtual: true
        field :password_hash, :string

        timestamps()
      end

We have ourselves added the following field to the schema.

    field :password, :string, virtual: true

This is a virtual field created usually to hold the password at an intermediate state before we can hash it and store it to the database.

We shall also have a look at our migration file used to create a users table here.

    # priv/repo/migrations/20170606102134_create_user.exs

    def change do
      create table(:users) do
        add :first_name, :string
        add :last_name, :string
        add :email, :string, null: false
        add :password_hash, :string
        timestamps()
      end

      create unique_index(:users, [:email])
    end

As we should have noticed, we do not have our virtual password field listed above. It is just an intermediate field to help in hashing. We have also added a unique index to our email column. By this, we mean to implement that we shall restrict an email to get registered with only one account.

Great. Now to do anything with our app we need a controller. Let's get to that. We will have our user controller with the following actions it.

    # web/controllers/user_controller.ex

    defmodule Jod.UserController do
      use Jod.Web, :controller
      alias Jod.User
      plug :scrub_params, "user" when action in ~w(create)a

      # To show the list of users
      def index(conn, _params) do
      end
      
      # New and Create actions to create a new user
      def new(conn, _params) do
        
      end

      def create(conn, %{"user" => user_params}) do
        
      end

      # Show and Update actions to let the users to view and edit their data.       
      def show(conn, %{"id" => id}) do
        
      end

      def update(conn, %{"id" => id, "user" => user_params}) do
        
      end
    end

We have also included the :scrub_params function plug in the beginning that shall convert all the blank string params into nils.

With the controller in place, we shall also define our view. For now, it may have no actions defined in it. We shall define if required.

    # /web/views/user_view.ex

    defmodule Jod.UserView do
      use Jod.Web, :view
    end

Okay, We will get back to the model and have few good work done. We shall hash the incoming visible password and store it to our database. For this, we shall use comeonin. Let's get that added.

Add comeonin to our set of dependencies.

    # mix.exs

    defp deps do
      [ {:comeonin, "~> 3.0"} ]
    end

And also as an application dependency.

    # In the same file, mix.exs
    
    def application do
      [mod: {Jod, []},
      applications: [:phoenix, :phoenix_pubsub, :phoenix_html, :cowboy, :logger, :gettext, :phoenix_ecto, :postgrex, :comeonin]]
    end

After getting the dependencies, we shall use comeonin. But before that, we need to define our changeset in the User model. Let's do that and continue with comeonin.

Before we put the data into the database we need to define our user and validate the value it contains and one among them is the password hashing.

We define required and optional fields. We check the e-mail to be a valid entry and also a unique one. We then hash the password and store it in the database. The flow, at first sight, may look a little confusing, but we will get to know how it works when called from the user controller. We will actually call the registration_changeset which in itself calls the changeset.

    # web/models/user.ex

    @required_fields ~w(first_name email)a
    @optional_fields ~w(last_name)a

    def changeset(struct, params \\ %{}) do
      struct
      |> cast(params, @required_fields ++ @optional_fields)
      |> validate_required(@required_fields)
      |> validate_format(:email, ~r/@/)
      |> unique_constraint(:email)
    end

    def registration_changeset(struct, params) do
      struct
      |> changeset(params)
      |> cast(params, ~w(password)a)
      |> validate_length(:password, min: 6)
      |> generate_password_hash()
    end

And, as you noticed we are yet to implement the generate_password_hash function. It’s simple and private ;)

    # web/models/user.ex
    defp generate_password_hash(changeset) do
      case changeset do
        %Ecto.Changeset{valid?: true, changes: %{password: pass}} ->
          put_change(changeset, :password_hash, Comeonin.Bcrypt.hashpwsalt(pass))
      _ ->
          changeset
      end
    end

We initially check if the changeset is valid. If so, we hash the password. If not, which can be a rare case as we make the same check before entering this function, we will return the changeset untouched.

Now, we shall create a user and save the data to the database. Wait! Are we going to create the user using the terminal?

:p

That's a good idea to test and develop, but we will make UI forms for the same.
With our view already defined, let's move to templates. Following is the form to create a new user.

    # web/templates/new.html.eex

    <div class="row">
      <div class="card  blue-grey lighten-5 col s4 offset-s4">
        <div class="card-content">
          <%= form_for @changeset, user_path(@conn, :create), fn f -> %>

            <div class="input-field">
              <%= text_input f, :first_name, id: "first_name", class: "validate" %>
              <label for="first_name">First Name</label>
            </div>

            <div class="input-field">
              <%= text_input f, :last_name, id: "last_name", class: "validate" %>
              <label for="last_name">Last Name</label>
            </div>

            <div class="input-field">
              <%= text_input f, :email, id: "email_id", type: "email", class: "validate" %>
              <label for="email" data-error="Please enter a valid email address" data-success="">Email</label>
              <%= error_tag f, :email %>
            </div>

            <div class="input-field">
              <%= password_input f, :password, id: "password_field", type: "password", class: "validate" %>
              <label for="password_field">Password</label>
              <%= error_tag f, :password %>
            </div>

            <div class="row">
              <%= submit "Create new account", class: "btn col s6 offset-s6" %>
            </div>
          <% end %>
        </div>
      </div>
    </div>

We also have few class names in the snippet that are related to materialize-css library. Most of the class names are self-explanatory. But for any noticed weird names, you may please refer the [docs](http://materializecss.com/).

But how shall we reach this page? We haven’t defined them in the controller action. And to define them there, we need to define the routes.

So first things first. We will define the routes.

    # /web/router.ex
    scope "/", Jod do
      pipe_through [:browser]
      get "/", PageController, :index
      resources "/users", UserController, only: [:new, :create]
    end

We have restricted it to only new and create action. As we shall add other actions later which a user will be able to reach only after being authenticated. That sounds reasonable, right?

Now new and create actions get defined in the controller.

    # web/controllers/user_controller.ex

    def new(conn, _params) do
      changeset = User.changeset(%User{})
      render(conn, "new.html", changeset: changeset)
    end
    def create(conn, %{"user" => user_params}) do
      changeset = %User{} |> User.registration_changeset(user_params)
    case Repo.insert(changeset) do
        {:ok, user} -> 
          conn
          |> put_flash(:info, "Welcome #{user.name}!")
          |> redirect(to: page_path(conn, :index))
        {:error, changeset} -> 
          conn
          |> render("new.html", changeset: changeset)
      end
    end

If we can notice, we call the registration_changeset on the User and then pass the params. It calls the default changeset within itself.

Good. We will now come to the core part of authentication. We have followed few steps to setup Guardian. We shall look at them all in one go.

Guardian being added to the list of dependencies.

    # mix.exs

    defp deps do
      [
        # ...
        {:guardian, "~> 0.14"}
        # ...
      ]
    end


    # config.exs

    config :guardian, Guardian,
      allowed_algos: ["HS512"], # optional
      verify_module: Guardian.JWT,  # optional
      issuer: "Jod",
      ttl: { 30, :days },
      allowed_drift: 2000,
      verify_issuer: true, # optional
      secret_key: "<Secret key>",
      serializer: Jod.GuardianSerializer

Also, we need to add the default Guardian serializer to the app. We shall have a new directory to keep the code organised instead of putting them in some random folders.

    # /web/auth/guardian_serializer.ex

    defmodule Jod.GuardianSerializer do
      @behaviour Guardian.Serializer
      alias Jod.Repo
      alias Jod.User
      def for_token(user = %User{}), do: { :ok, "User:#{user.id}" }
      def for_token(_), do: { :error, "Unknown resource type" }
      def from_token("User:" <> id), do: { :ok, Repo.get(User, id) }
      def from_token(_), do: { :error, "Unknown resource type" }
    end

We shall also add a Guardian error handler, use of which we will see soon.

    # /web/auth/guardian_error_handler.ex

    defmodule SimpleAuth.GuardianErrorHandler do
      import Phoenix.Controller
      import Jod.Router.Helpers
      
      def unauthenticated(conn, _params) do
        conn
        |> put_flash(:info, "Please sign-in to access this page")
        |> redirect(to: session_path(conn, :new))
      end
      def unauthorized(conn, _params) do
        conn
        |> put_flash(:info, "Please sign-in to access this page")
        |> redirect(to: session_path(conn, :new))
      end
    end

With Guardian being added, we will now be able to manage sessions. Let's start with the sessions controller.

    defmodule Jod.SessionController do
      use Jod.Web, :controller

      plug :scrub_params, "session" when action in ~w(create)a

      # To create a new session. (Login)
      def new(conn, _) do
        
      end

      def create(conn, %{"session" => %{"email" => user, 
                                        "password" => pass}}) do
        
      end

      # To delete a session. (Logout)
      def delete(conn, _params) do
        
      end
    end

And appropriately for the actions defined, we shall define the routes.

    # /web/router.ex

    scope "/", Jod do
      pipe_through [:browser]
      get "/", PageController, :index
      resources "/users", UserController, only: [:new, :create]
      resources "/sessions", SessionController, only: [:new, :create, :delete]
    end

But if we look at our routes more carefully, the whole application is accessible to anyone. To implement authentication we need to make necessary changes to the routes. That stands as our first step to implement authenticate users.

We should have noticed the default :browser pipleline in the routes file. Along with it, we shall be adding few more. With our changes, our routes file will look like the following.


    pipeline :with_session do
      plug Guardian.Plug.VerifySession
      plug Guardian.Plug.LoadResource
    end

    pipeline :browser_auth do
      plug Guardian.Plug.VerifySession
      plug Guardian.Plug.EnsureAuthenticated, handler: Jod.GuardianErrorHandler
      plug Guardian.Plug.LoadResource

    scope "/", Jod do
      # Login not required for accessing this section
      pipe_through [:browser, :with_session] 

      get "/", PageController, :index
      resources "/users", UserController, only: [:new, :create]
      resources "/sessions", SessionController, only: [:new, :create, :delete]

      # Login required to access the below.
      scope "/", Jod do
        pipe_through [:browser_auth]

        resources "/users", UserController, only: [:show, :index, :update]
        resources "/submissions", SubmissionController

      end
    end

It makes more sense now. We demand the user to be logged in to access the user-specific information and also to look at the list of users. That seems to have been achieved using Guardian. But what do they actually do is the following.

> Guardian.Plug.VerifySession: 
  Looks for a token in the session. Useful for browser sessions. If one is not found, this does nothing. 

> Guardian.Plug.EnsureAuthenticated: 
  Looks for a previously verified token. If one is found, continues, otherwise, it will call the :unauthenticated function of your handler. 

> Guardian.Plug.LoadResource: 
  The LoadResource plug looks in the subfield of the token fetches the resource from the Serializer and makes it available via Guardian.Plug.current_resource(conn)

Now, we shall create the login form for the user to log in and then create a session.

    #web/controllers/session_controller.ex

    def new(conn, _) do
      render conn, "new.html"
    end

And a view and its corresponding template.

    #web/views/session_view.ex

    defmodule Jod.SessionView do
      use Jod.Web, :view
    end


    #web/templates/session/new.html.eex

    <div class="row">
      <div class="card  blue-grey lighten-5 col s4 offset-s4">
        <div class="card-content">
          <%= form_for @conn, session_path(@conn, :create), [as: :session], fn f -> %>
            <div class="input-field">
              <%= text_input f, :email, id: "email_id", type: "email", class: "validate" %>
              <label for="email" data-error="Please enter a valid email address" data-success="">Email</label>
            </div>

            <div class="input-field">
              <%= password_input f, :password, id: "password_field", type: "password", class: "validate" %>
              <label for="password_field">Password</label>
            </div>

            <div class="row">
              <%= submit "Sign in", class: "btn col s4 offset-s8" %>
            </div>
          <% end %>
        </div>
      </div>
    </div>

As we can see, on this form to log in will attempt to create a session as mentioned in it. We shall now define the create action in the session controller.

    #web/controllers/session_controller.ex

    def create(conn, %{"session" => %{"email" => user, 
                                      "password" => pass}}) do
      case Jod.Auth.login_by_email_and_pass(conn, user, pass, repo: Repo) do
        
        {:ok, conn} ->
          conn
          |> put_flash(:info, "Logged In")
          |> redirect(to: page_path(conn, :index))
        
        {:error, _reason, conn} ->
          conn
          |> put_flash(:error, "Please check your credentials")
          |> render("new.html")
      end
    end

We recently created an auth directory, right? We shall have our login logic inside it. As we see, we call an action called login_by_email_and_pass in auth.ex file located in the web/auth directory.

    # web/auth/auth.ex

    defmodule Jod.Auth do
      import Comeonin.Bcrypt, only: [checkpw: 2, dummy_checkpw: 0]
      import Plug.Conn #Check

      def login(conn, user) do
        conn
        |> Guardian.Plug.sign_in(user, :access)
      end

      def login_by_email_and_pass(conn, email, given_pass, opts) do
        repo = Keyword.fetch!(opts, :repo)
        user = repo.get_by(Jod.User, email: email)

        cond do
          user && checkpw(given_pass, user.password_hash) ->
            {:ok, login(conn, user)}
          user ->
            {:error, :unauthenticated, conn}
          true ->
            dummy_checkpw()
            {:error, :not_found, conn}
        end
      end
    end

So far, we seem to have handled things rightly. Guardian came handy to sign_in and create a session and also comeonin came in handy again to decrypt and check the password that is hashed by comeonin and stored in our database.

Shall we move to sign out part of it, now?

The delete action gets defined as the first step which in fact does all the work required.

    # web/controllers/session_controller.ex

    def delete(conn, _params) do
      conn
      |> Guardian.Plug.sign_out
      |> put_flash(:info, "Logged out successfully.")
      |> redirect(to: page_path(conn, :index))
    end

Do you prefer to also move this single line "Guardian.Plug.sign_out" to the auth directory and call it here by its function name? We are keeping this here for now.

We also need to change the state of the sign in and sign out buttons as we proceed further.

At this point, we have to check if a user is logged in and act accordingly. In future, we may also need to check who the current user is, right? So why don't we implement the current user functionality, just now?

    # web/auth/current_user.ex

    defmodule Jod.CurrentUser do
      import Plug.Conn
      import Guardian.Plug

      def init(opts), do: opts

      def call(conn, _opts) do
        current_user = current_resource(conn)
        assign(conn, :current_user, current_user)
      end
    end

This plug just gets current_resource from a Guardian token and assigns it as property to our connection. So, now we can access signed in user through @current_user variable (connection assignment).

But we need to integrate it in our project. Where shall we call this and get the current_user assigned? A good place to do it may be the :with_session pipeline that we have defined in our routes.

    # web/route.ex

    pipeline :with_session do
      plug Guardian.Plug.VerifySession
      plug Guardian.Plug.LoadResource
      plug Jod.CurrentUser
    end

By adding it here, we make sure that the CurrentUser module will have the necessary information to fetch and assign the current_user property.

We will now head back to sign in/sign out option switches. When the current user is present, we would show the sign-out option and if not allow the user to sing in. We can have it in a partial file and render it in the site header.

    # /web/templates/layout/sign_in_sign_out.html.eex

    <%= if @current_user do %>
    <li>
        <%= link "Sign out", to: session_path(@conn, :delete, @current_user),
                                method: "delete" %>
    </li>
    <% else %>
      <li><%= link "Create new account", to: user_path(@conn, :new),
          class: "" %></li>
      <li><%= link "Sign in", to: session_path(@conn, :new),
          class: "" %></li>
    <% end %>

With this, we have successfully implemented ***simple*** user authentication in our project. 


